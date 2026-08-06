package wireguard

func topologyNode(topo Topology, id string) *Node {
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == id {
			return &topo.Nodes[i]
		}
	}
	return nil
}
