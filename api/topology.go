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

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/abbot/go-http-auth"
	shttp "github.com/connetos/anywatch/http"
	"github.com/connetos/anywatch/logging"
	"github.com/connetos/anywatch/topology/graph"
	"github.com/connetos/anywatch/topology/graph/traversal"
	"github.com/connetos/anywatch/topology/probes"
	"github.com/connetos/anywatch/validator"
)

const (
	DetectConfigFile = "etc/topology_detect.json"
)

// TopologyAPI exposes the topology query API
type TopologyAPI struct {
	gremlinParser *traversal.GremlinTraversalParser
	TDClient      *probes.TopologyDetectClient
}

// TopologyParam topology API parameter
type TopologyParam struct {
	GremlinQuery string `json:"GremlinQuery,omitempty" valid:"isGremlinExpr"`
}

type TopologyDetect struct {
	IP        string
	Period    int64
	Community string
}

type DetectConfig struct {
	Detectip     string
	Detectperiod int
	Community    string
}

func (t *TopologyAPI) graphToDot(w http.ResponseWriter, g *graph.Graph) {
	g.RLock()
	defer g.RUnlock()

	w.Write([]byte("digraph g {\n"))

	nodeMap := make(map[graph.Identifier]*graph.Node)
	for _, n := range g.GetNodes(nil) {
		nodeMap[n.ID] = n
		name, _ := n.GetFieldString("Name")
		title := fmt.Sprintf("%s-%s", name, n.ID[:7])
		label := title
		for k, v := range n.Metadata() {
			switch k {
			case "Type", "IfIndex", "State", "TID":
				label += fmt.Sprintf("\\n%s = %v", k, v)
			}
		}
		w.Write([]byte(fmt.Sprintf("\"%s\" [label=\"%s\"]\n", title, label)))
	}

	for _, e := range g.GetEdges(nil) {
		parent := nodeMap[e.GetParent()]
		child := nodeMap[e.GetChild()]
		if parent == nil || child == nil {
			continue
		}

		childName, _ := child.GetFieldString("Name")
		parentName, _ := parent.GetFieldString("Name")
		relationType, _ := e.GetFieldString("RelationType")
		linkLabel, linkType := "", "->"
		switch relationType {
		case "":
		case "layer2":
			linkType = "--"
			fallthrough
		default:
			linkLabel = fmt.Sprintf(" [label=%s]\n", relationType)
		}
		link := fmt.Sprintf("\"%s-%s\" %s \"%s-%s\"%s", parentName, parent.ID[:7], linkType, childName, child.ID[:7], linkLabel)
		w.Write([]byte(link))
	}

	w.Write([]byte("}"))
}

func (t *TopologyAPI) topologyIndex(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	g := t.gremlinParser.Graph
	g.RLock()
	defer g.RUnlock()

	w.WriteHeader(http.StatusOK)
	if strings.Contains(r.Header.Get("Accept"), "vnd.graphviz") {
		w.Header().Set("Content-Type", "text/vnd.graphviz; charset=UTF-8")
		t.graphToDot(w, g)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		if err := json.NewEncoder(w).Encode(g); err != nil {
			panic(err)
		}
	}
}

func (t *TopologyAPI) topologySearch(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	resource := TopologyParam{}

	data, _ := ioutil.ReadAll(r.Body)
	if len(data) != 0 {
		if err := json.Unmarshal(data, &resource); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := validator.Validate(resource); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	if resource.GremlinQuery == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ts, err := t.gremlinParser.Parse(strings.NewReader(resource.GremlinQuery), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	res, err := ts.Exec()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "vnd.graphviz") {
		if graphTraversal, ok := res.(*traversal.GraphTraversal); ok {
			w.Header().Set("Content-Type", "text/vnd.graphviz; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			t.graphToDot(w, graphTraversal.Graph)
		} else {
			writeError(w, http.StatusNotAcceptable, errors.New("Only graph can be outputted as dot"))
		}
	} else {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			panic(err)
		}
	}
}

func (t *TopologyAPI) requestToParams(td *TopologyDetect) (*probes.TopologyDetect, error) {

	tdr := &probes.TopologyDetect{
		IP:        td.IP,
		Period:    td.Period,
		Community: td.Community,
	}

	return tdr, nil
}

func (t *TopologyAPI) topologyDetect(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	decoder := json.NewDecoder(r.Body)
	var dt *TopologyDetect = new(TopologyDetect)
	//var dt probes.TopologyDetect
	if err := decoder.Decode(dt); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer r.Body.Close()

	logging.GetLogger().Debugf("topologyDetect IP %s community %s", dt.IP, dt.Community)

	dtInfo, _ := t.requestToParams(dt)

	_, err := t.TDClient.DetectTopology(dtInfo)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(dt); err != nil {
		panic(err)
	}
}

func (t *TopologyAPI) topologyDetectDelete(w http.ResponseWriter, r *auth.AuthenticatedRequest) {

	var dt = &TopologyDetect{
		IP:        "",
		Period:    0,
		Community: "",
	}
	logging.GetLogger().Debugf("topologyDetectDelete")

	dtInfo, _ := t.requestToParams(dt)

	_, err := t.TDClient.DetectTopologyDelete(dtInfo)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(dt); err != nil {
		panic(err)
	}
}

func (t *TopologyAPI) topologyDetectConfig(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	var dt *TopologyDetect = new(TopologyDetect)

	logging.GetLogger().Debugf("topologyDetect IP %s community %s", dt.IP, dt.Community)
	raw, err := ioutil.ReadFile(DetectConfigFile)
	if err != nil {
		logging.GetLogger().Errorf("snmp read JSON file failed, err %s", err.Error())
		return
	}
	config := DetectConfig{}
	err = json.Unmarshal([]byte(raw), &config)
	if err != nil {
		logging.GetLogger().Debug("snmp Unmarshal JSON file failed, err %s", err.Error())
		return
	}
	logging.GetLogger().Debugf("topologyDetectConfig IP %s, period %d community %s", config.Detectip, config.Detectperiod, config.Community)

	dt.IP = config.Detectip
	dt.Period = int64(config.Detectperiod)
	dt.Community = config.Community

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(dt); err != nil {
		panic(err)
	}
}

func (t *TopologyAPI) registerEndpoints(r *shttp.Server) {
	routes := []shttp.Route{
		{
			Name:        "TopologiesIndex",
			Method:      "GET",
			Path:        "/api/topology",
			HandlerFunc: t.topologyIndex,
		},
		{
			Name:        "TopologiesSearch",
			Method:      "POST",
			Path:        "/api/topology",
			HandlerFunc: t.topologySearch,
		},

		{
			Name:        "TopologiesDetect",
			Method:      "POST",
			Path:        "/api/detectTopology",
			HandlerFunc: t.topologyDetect,
		},
		{
			Name:        "TopologiesDetectConfig",
			Method:      "GET",
			Path:        "/api/detectTopologyConfig",
			HandlerFunc: t.topologyDetectConfig,
		},
		{
			Name:        "TopologiesDetectDelete",
			Method:      "DELETE",
			Path:        "/api/detectTopologyDelete",
			HandlerFunc: t.topologyDetectDelete,
		},
	}

	r.RegisterRoutes(routes)
}

// RegisterTopologyAPI registers a new topology query API
func RegisterTopologyAPI(r *shttp.Server, parser *traversal.GremlinTraversalParser, tdc *probes.TopologyDetectClient) {
	t := &TopologyAPI{
		gremlinParser: parser,
		TDClient:      tdc,
	}

	t.registerEndpoints(r)
}
