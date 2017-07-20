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
	"bytes"
	"fmt"
	"net/http"

	"github.com/connetos/anywatch/common"
	shttp "github.com/connetos/anywatch/http"
	"github.com/connetos/anywatch/logging"
	"github.com/connetos/anywatch/topology/graph"
)

const (
	Namespace = "Topology_Detect"
)

type TopologyDetectServer struct {
	shttp.DefaultWSClientEventHandler
	WSAsyncClientPool *shttp.WSAsyncClientPool
	Graph             *graph.Graph
}

func (td *TopologyDetectServer) detectTopology(msg shttp.WSMessage) error {
	var dt *TopologyDetect = new(TopologyDetect)
	if err := common.JSONDecode(bytes.NewBuffer([]byte(*msg.Obj)), dt); err != nil {
		return fmt.Errorf("Unable to decode packet inject param message %v", msg)
	}

	TopologyDetectChan <- dt

	return nil
}

func (td *TopologyDetectServer) OnMessage(c *shttp.WSAsyncClient, msg shttp.WSMessage) {
	switch msg.Type {
	case "TDRequest":
		var reply *shttp.WSMessage
		err := td.detectTopology(msg)
		replyObj := &TopologyDetectReply{err: err}
		if err != nil {
			logging.GetLogger().Error(err.Error())
			reply = msg.Reply(replyObj, "TDResult", http.StatusBadRequest)
		} else {
			reply = msg.Reply(replyObj, "TDResult", http.StatusOK)
		}

		c.SendWSMessage(reply)
	}
}

func NewServer(wspool *shttp.WSAsyncClientPool, graph *graph.Graph) *TopologyDetectServer {
	s := &TopologyDetectServer{
		WSAsyncClientPool: wspool,
		Graph:             graph,
	}
	wspool.AddEventHandler(s, []string{Namespace})

	return s
}
