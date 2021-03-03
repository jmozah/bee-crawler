// Copyright 2020 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hive exposes the hive protocol implementation
// which is the discovery protocol used to inform and be
// informed about other peers in the network. It gossips
// about all peers by default and performs no specific
// prioritization about which peers are gossipped to
// others.
package hive

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ethersphere/bee/pkg/addressbook"
	"github.com/ethersphere/bee/pkg/bzz"
	"github.com/ethersphere/bee/pkg/hive/pb"
	"github.com/ethersphere/bee/pkg/logging"
	"github.com/ethersphere/bee/pkg/p2p"
	"github.com/ethersphere/bee/pkg/p2p/protobuf"
	"github.com/ethersphere/bee/pkg/swarm"
)

const (
	protocolName    = "hive"
	protocolVersion = "1.0.0"
	peersStreamName = "peers"
	messageTimeout  = 1 * time.Minute // maximum allowed time for a message to be read or written.
	maxBatchSize    = 30
)

type Service struct {
	streamer        p2p.Streamer
	addressBook     addressbook.GetPutter
	addPeersHandler func(context.Context, ...swarm.Address) error
	networkID       uint64
	sqliteDB        *sql.DB
	logger          logging.Logger
}

func New(streamer p2p.Streamer, addressbook addressbook.GetPutter, networkID uint64, sqliteDB *sql.DB, logger logging.Logger) *Service {
	return &Service{
		streamer:    streamer,
		logger:      logger,
		addressBook: addressbook,
		networkID:   networkID,
		sqliteDB:    sqliteDB,
	}
}

func (s *Service) Protocol() p2p.ProtocolSpec {
	return p2p.ProtocolSpec{
		Name:    protocolName,
		Version: protocolVersion,
		StreamSpecs: []p2p.StreamSpec{
			{
				Name:    peersStreamName,
				Handler: s.peersHandler,
			},
		},
	}
}

func (s *Service) BroadcastPeers(ctx context.Context, addressee swarm.Address, peers ...swarm.Address) error {
	max := maxBatchSize
	for len(peers) > 0 {
		if max > len(peers) {
			max = len(peers)
		}
		if err := s.sendPeers(ctx, addressee, peers[:max]); err != nil {
			return err
		}

		peers = peers[max:]
	}

	return nil
}

func (s *Service) SetAddPeersHandler(h func(ctx context.Context, addr ...swarm.Address) error) {
	s.addPeersHandler = h
}

func (s *Service) sendPeers(ctx context.Context, peer swarm.Address, peers []swarm.Address) (err error) {
	stream, err := s.streamer.NewStream(ctx, peer, nil, protocolName, protocolVersion, peersStreamName)
	if err != nil {
		return fmt.Errorf("new stream: %w", err)
	}
	defer func() {
		if err != nil {
			_ = stream.Reset()
		} else {
			_ = stream.FullClose()
		}
	}()
	//w, _ := protobuf.NewWriterAndReader(stream)
	var peersRequest pb.Peers
	for _, p := range peers {
		addr, err := s.addressBook.Get(p)
		if err != nil {
			if err == addressbook.ErrNotFound {
				s.logger.Debugf("hive broadcast peers: peer not found in the addressbook. Skipping peer %s", p)
				continue
			}
			return err
		}

		peersRequest.Peers = append(peersRequest.Peers, &pb.BzzAddress{
			Overlay:   addr.Overlay.Bytes(),
			Underlay:  addr.Underlay.Bytes(),
			Signature: addr.Signature,
		})
	}

	//if err := w.WriteMsgWithContext(ctx, &peersRequest); err != nil {
	//	return fmt.Errorf("write Peers message: %w", err)
	//}

	return nil
}

func (s *Service) peersHandler(ctx context.Context, peer p2p.Peer, stream p2p.Stream) error {
	_, r := protobuf.NewWriterAndReader(stream)
	ctx, cancel := context.WithTimeout(ctx, messageTimeout)
	defer cancel()
	var peersReq pb.Peers
	if err := r.ReadMsgWithContext(ctx, &peersReq); err != nil {
		_ = stream.Reset()
		return fmt.Errorf("read requestPeers message: %w", err)
	}

	// close the stream before processing in order to unblock the sending side
	// fullclose is called async because there is no need to wait for confirmation,
	// but we still want to handle not closed stream from the other side to avoid zombie stream
	go stream.FullClose()

	var peers []swarm.Address
	var bzzPeers []*bzz.Address
	count := 0
	for _, newPeer := range peersReq.Peers {
		bzzAddress, err := bzz.ParseAddress(newPeer.Underlay, newPeer.Overlay, newPeer.Signature, s.networkID)
		if err != nil {
			s.logger.Warningf("skipping peer in response %s: %v", newPeer.String(), err)
			continue
		}

		err = s.addressBook.Put(bzzAddress.Overlay, *bzzAddress)
		if err != nil {
			s.logger.Warningf("skipping peer in response %s: %v", newPeer.String(), err)
			continue
		}

		peers = append(peers, bzzAddress.Overlay)
		bzzPeers = append(bzzPeers, bzzAddress)
		err = s.addPeer(peer.Address, bzzAddress.Overlay)
		if err != nil {
			s.logger.Errorf("HANDLE_PEERS: %v", err.Error())
			continue
		}
		count ++
	}

	if s.addPeersHandler != nil {
		if err := s.addPeersHandler(ctx, peers...); err != nil {
			return err
		}
	}
	err := s.updatePeerCount(peer.Address.String(), count)
	if err != nil {
		s.logger.Errorf("HANDLE_PEERS: %v", err.Error())
		return err
	}
	err = s.addNeighboursAsPeers(bzzPeers)
	if err != nil {
		s.logger.Errorf("HANDLE_PEERS: %v", err.Error())
		return err
	}

	return nil
}

func (s *Service) addPeer(baseOverlay swarm.Address, neighbourOverlay swarm.Address) error {
	// Insert the neighbour into neighbour info table
	insertStatement := `insert into NEIGHBOUR_INFO (BASE_OVERLAY, PROXIMITY_ORDER,  NEIGHBOUR_OVERLAY) values (?, ?, ?)`
	statement, err := s.sqliteDB.Prepare(insertStatement)
	if err != nil {
		return err
	}
	defer statement.Close()

	po := swarm.Proximity(baseOverlay.Bytes(), neighbourOverlay.Bytes())
	_, err = statement.Exec(baseOverlay.String(), po, neighbourOverlay.String())
	if err != nil {
		if strings.HasPrefix(err.Error(), "UNIQUE") {
			s.logger.Errorf("HANDLE_PEERS: inserted neighbour %s for overlay %s already, so ignoring it", neighbourOverlay.String(), baseOverlay.String())
			return nil
		}
		return err
	}
	s.logger.Infof("HANDLE_PEERS: inserted neighbour %s for overlay %s", neighbourOverlay.String(), baseOverlay.String())
	return nil
}

func (s *Service) updatePeerCount(baseOverlay string, count int) error {
	updateStatement := `update PEER_INFO set PEERS_COUNT = PEERS_COUNT + ? WHERE OVERLAY = ?`
	statement, err := s.sqliteDB.Prepare(updateStatement)
	if err != nil {
		return err
	}
	defer statement.Close()

	_, err = statement.Exec(count, baseOverlay)
	if err != nil {
		return err
	}
	s.logger.Debugf("HANDLE_PEERS: incremented peer count of %s by another %d", baseOverlay, count)
	return nil
}

func (s *Service) addNeighboursAsPeers(bzzPeers []*bzz.Address) error {
	for _, bzzPeer := range bzzPeers {
		rows, err := s.sqliteDB.Query("select OVERLAY from PEER_INFO WHERE OVERLAY = '%s' \n", bzzPeer.Overlay.String())
		if err != nil {
			return err
		}
		defer rows.Close()

		overlayPresent := ""
		for rows.Next() {
			err := rows.Scan(&overlayPresent)
			if err != nil {
				return err
			}
		}
		if overlayPresent == "" {
			insertStatement := `insert into PEER_INFO (OVERLAY, IP4or6, IP, PROTOCOL, PORT, UNDERLAY, PEERS_COUNT) values (?, ?, ?, ?, ?, ?, ?)`
			statement, err := s.sqliteDB.Prepare(insertStatement)
			if err != nil {
				return err
			}
			defer statement.Close()

			peers_count := -1
			overlay := bzzPeer.Overlay.String()
			underlay := bzzPeer.Underlay.String()
			cols := strings.Split(underlay, "/")
			if len(cols) != 7 {
				return fmt.Errorf("invalid underlay format %s", underlay)
			}

			_, err = statement.Exec(overlay, cols[1], cols[2], cols[3], cols[4], cols[6], peers_count)
			if err != nil {
				if strings.HasPrefix(err.Error(), "UNIQUE") {
					s.logger.Debugf("HANDLE_PEERS: peer %s already got added in PEER_INFO, so ignoring it", overlay)
					return nil
				}
				return err
			}
			s.logger.Debugf("HANDLE_PEERS: adding neighbour %s as new harvested peer since it is not present in PEER_INFO", overlay)
		}
	}
	return nil
}