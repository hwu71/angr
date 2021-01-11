import logging

import networkx

from . import Analysis

from ..code_location import CodeLocation

_l = logging.getLogger(name=__name__)

class PDG(Analysis):
    """
    Implements a program dependence graph.
    """
    
    def __init__(self, cdg, ddg, start=None):
        """
        Constructor.

        :param cdg:			The control dependence graph upon which this program dependence graph will build
        :param ddg:			The data dependence graph upon which this program dependence graph will build
        :param start:		The starting point to begin constructing the program dependence graph
        """
        self._start = start if start is not None else self.project.entry
        self._cdg = cdg
        self._ddg = ddg 

        # analysis output
        self._graph = None
        
        # analysis output for Spider
        self._directly_affected_stmts = None
        self._indirectly_affected_stmts = None
        
        # Begin construction!
        self._construct()
	
    #
    # Properties
    #

    @property
    def graph(self):
        """
        :returns: A networkx DiGraph instance representing the program dependence graph.
        :rtype: networkx.DiGraph
        """

        return self._graph

    #
    # Public methods
    #

    def pp(self):
        """
        Pretty printing.
        """	
        for src, dst, data in self.graph.edges(data=True):
                print("%s <-- %s, %s" % (src, dst, data))
    
    def get_reachable_stmts(self, block_addrs):     
        """
        Get all the reachble statements(including directly affected statements 
        and indirectly affected statements) in the PDG graph with the block 
        addresses.
        
        :param set block_addrs: The addresses of the target blocks.
        :return: directly affected stmts and indirectly affected stmts
        :rtype: list, list
        """
        self._get_reachable_stmts(block_addrs)
        
        directly_affected_stmts_info = [(node.block_addr, node.stmt_idx) for node in self._directly_affected_stmts]
        indirectly_affected_stmts_info = [(node.block_addr, node.stmt_idx) for node in self._indirectly_affected_stmts]
        
        return directly_affected_stmts_info, indirectly_affected_stmts_info

    #
    # Private methods
    #

    def _construct(self):
        """
        Contruct the program dependence graph.

        We track the following types of dependence:
        - statement dependencies in ddg
        - control dependencies in cdg 
        """
        self._graph = networkx.DiGraph()

        # 1. add all the stmt nodes into the graph

        # we need to consider both the ddg_stmt graph and the ddg_data graph 
        for node in self._ddg.graph.nodes:
            if node not in self._graph:
                self._graph_add_node(node)

        for data_node in self._ddg.data_graph.nodes:
            # type of 'data_node': angr.analyses.ddg.ProgramVariable
            # type of 'node': angr.code_location.CodeLocation
            node = data_node.location
            if node not in self._graph:
                self._graph_add_node(node)

        # 2. add edges from ddg and cdg

        # 2.1 from the ddg stmt graph
        for src, dst in self._ddg.graph.edges:
            self._graph_add_edge(src, dst, type='dd')

        # 2.2 from the cdg 
        for src, dst in self._cdg.graph.edges:
            if src.irsb is None:
                continue 
            
            src_block_addr = src.addr 
            assert(len(src.irsb.exit_statements)==1)
            _, src_exit_stmt_idx, _ = src.irsb.exit_statements[0]
			
            dst_block_addr = dst.addr

            src_location = self._get_node_from_graph(src_block_addr, src_exit_stmt_idx)

            for location in self._graph.nodes:
                if(location.block_addr == dst_block_addr):
                    self._graph_add_edge(src_location, location, type='cd')
    
    def _get_reachable_stmts(self, block_addrs):
        """
        Get all the reachble statements(including directly affected statements 
        and indirectly affected statements) in the PDG graph with the block 
        addresses.
        
        :param set block_addrs: The addresses of the target blocks.
        :return: None       
        """
        graph = self._graph 
        
        _directly_affected_stmts = []
        for node in graph.nodes:
            if node.block_addr in block_addrs:
                _directly_affected_stmts.append(node)
        self._directly_affected_stmts = _directly_affected_stmts.copy()
        
        queue = _directly_affected_stmts
        _indirectly_affected_stmts = []
        
        while queue:
            src = queue.pop()
            for successor in graph.successors(src):
                if successor not in self._directly_affected_stmts and \
                    successor not in _indirectly_affected_stmts:
                    _indirectly_affected_stmts.append(successor)
                    queue.append(successor)
        
        self._indirectly_affected_stmts = _indirectly_affected_stmts
        
        

    
    def _get_directly_affected_stmts(self, block_addrs):
        """
        Get all the directly affected statements in the pdg graph with the 
        block addresses.
        
        :param set block_addrs: The addresses of the target blocks.
        :return: a list of directly affected stmt nodes 
        :rtype: list 
        """
        return [node for node in self._graph.nodes if node.block_addr in block_addrs]
                

    #
    # Graph operations
    #

    def _graph_add_node(self, node):
        """
        Add a node in the program dependence graph.
        
        :param ProgramVariable node: The node to add.
        :return: None
        """
        self._graph.add_node(node)

    def _graph_add_edge(self, src, dst, **edge_labels):
        """
        Add an edge in the program dependence graph from a program location `src` to another program location `dst`.

        :param CodeLocation src: Source node.
        :param CodeLocation dst: Destination node.
        :param edge_labels: All labels associated with the edge.
        :return: None
        """

        # Is that edge already in the graph ?
        # If at least one is new, then we are not redoing the same path again
        if src in self._graph and dst in self._graph[src]:
            return

        self._graph.add_edge(src, dst, **edge_labels)

    def _get_node_from_graph(self, block_addr, stmt_idx):
    	"""
    	Find a node from the pdg graph by the block address and the statement index.

    	:param int block_addr: The block address of the target node.
    	:param int stmt_idx: The statement index of the target node.
    	:return: The target node in the graph
    	:rtype: CodeLocation
    	"""
    	target_node = None
    	for node in self._graph.nodes:
    		if(node.block_addr == block_addr and node.stmt_idx == stmt_idx):
    			target_node = node 
    			break 
    	return target_node
from angr.analyses import AnalysesHub
AnalysesHub.register_default('PDG', PDG)
