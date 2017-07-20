/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package probes

import (
	//"encoding/json"
	//"fmt"
	"sync"

	shttp "github.com/connetos/anywatch/http"
	"github.com/connetos/anywatch/logging"
)

type TopologyDetectReply struct {
	TrackingID string
	err        error
}

type TopologyDetectClient struct {
	shttp.DefaultWSServerEventHandler
	WSServer       *shttp.WSServer
	replyChanMutex sync.RWMutex
	replyChan      map[string]chan TopologyDetectReply
}

func (td *TopologyDetectClient) OnMessage(c *shttp.WSClient, m shttp.WSMessage) {
	td.replyChanMutex.RLock()
	defer td.replyChanMutex.RUnlock()

	/*
			ch, ok := td.replyChan[m.UUID]
			if !ok {
				logging.GetLogger().Errorf("Unable to send reply, chan not found for %s, available: %v", m.UUID, td.replyChan)
				return
			}

		var reply TopologyDetectReply
		if err := json.Unmarshal([]byte(*m.Obj), &reply); err != nil {
			ch <- TopologyDetectReply{err: fmt.Errorf("Failed to parse response from %s: %s", c.Host, err.Error())}
			return
		}

		ch <- reply
	*/
}

func (td *TopologyDetectClient) DetectTopology(dp *TopologyDetect) (string, error) {
	msg := shttp.NewWSMessage(Namespace, "TDRequest", dp)

	/*
		ch := make(chan PacketInjectorReply)
		defer close(ch)

		td.replyChan[msg.UUID] = ch
	*/

	//QueueBroadcastWSMessage
	td.WSServer.BroadcastWSMessage(msg)
	logging.GetLogger().Errorf("TopologyDetectClient DetectTopology msg %v", msg)

	return "", nil
}

func (td *TopologyDetectClient) DetectTopologyDelete(dp *TopologyDetect) (string, error) {
	msg := shttp.NewWSMessage(Namespace, "TDRequest", dp)
	td.WSServer.BroadcastWSMessage(msg)
	logging.GetLogger().Errorf("TopologyDetectClient DetectTopologyDelete msg %v", msg)

	return "", nil
}

func NewTopologyDetectClient(w *shttp.WSServer) *TopologyDetectClient {
	td := &TopologyDetectClient{
		WSServer:  w,
		replyChan: make(map[string]chan TopologyDetectReply),
	}
	w.AddEventHandler(td, []string{Namespace})

	return td
}
