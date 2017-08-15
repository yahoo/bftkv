// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

var cy = null;

function createNodes(edges, names) {
    console.log("creating nodes")
    nodes = []
    for (var key in names) {
        nodes.push({data: {id: key, name: names[key]}})
    }
    for(var i = 0; i < edges.length; i++) {
        if (!isInNodeArray(nodes, edges[i].Source)) {
            nodes.push({data: {id: edges[i].Source + "", name: names[edges[i].Source + ""]}})
        }
        if (!isInNodeArray(nodes, edges[i].Destination)) {
            nodes.push({data: {id: edges[i].Destination + "", name: names[edges[i].Destination + ""]}})
        }
    }

    console.log("Nodes: ")
    console.log(nodes)
    return nodes
}

function isInNodeArray(nodeArray, id) {
    //console.log("Questioned id: " + id)
    for(var i = 0; i < nodeArray.length; i++) {
        var node = nodeArray[i]

        //console.log(node)
        if (node.data.id == id) {
            return true
        }
    }
    return false
}


function createEdges(edges) {
    graphEdges = []
    console.log("Creating graph edges. ")
    for (var counter = 0; counter < edges.length; counter++) {
        var source = edges[counter].Source;
        var destination = edges[counter].Destination;

        // edge id = edge.source + edge.destination
        graphEdges.push({data: {id: source + destination, weight: 1, source, target: destination}})
   }

    // sort edges so that the graph will look the same
    graphEdges.sort(function(edge1, edge2) {
        return edge1.data.id.localeCompare(edge2.data.id)
    })

    return graphEdges
}

function buildGraph(data) {
    console.log("Data:")
    console.log(data)
    var nodes = createNodes(data.Edges, data.Names) // send the graph data too since we don't have the names for some nodes in the edges
    var edges = createEdges(data.Edges)

    // create the graph
    cy = cytoscape({container: document.getElementById("graph"), elements: {"nodes": nodes, "edges": edges},
    layout : {
        name: "dagre",
        roots: "#8E44AD",
        padding: 10
    },
    style : cytoscape.stylesheet().selector('node').css({'content': 'data(name)',
        'text-valign': 'center',
        'color': 'white',
        'width': 80,
        "height": 80,
        'text-outline-width': 2,
        'background-color': '#8E44AD',
        'text-outline-color': '#999'
    }).selector("edge")
    .css({
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'width': 4,
        'line-color': '#104FEB',
        'target-arrow-color': '#104FEB'})
    })
    markRevoked(data.Revoked)
}

function markRevoked(revokedArr) {
    if(revokedArr == null) {
        console.log("No nodes revoked.");
        return;
    }
    for (var i = 0; i < revokedArr.length; i++) {
            cy.filter('node[name="' + names[revokedArr[i]] + '"]').style({'background-color': 'red'})
            // clear edges going to and from the revoked node
            cy.filter('edge[target="' + revokedArr[i] +  '"]').remove();
            cy.filter('edge[source="' + revokedArr[i] +  '"]').remove();
    }
}

