var svg = d3.select("svg");

var width = svg.attr("width");
var height = svg.attr("height");

svg = svg.call(d3.zoom().on("zoom", zoomed)).append("g");

svg.append("defs").append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 20)
    .attr("refY", 0)
    .attr("markerWidth", 8)
    .attr("markerHeight", 8)
    .attr("orient", "auto")
  .append("svg:path")
    .attr("d", "M0,-5L10,0L0,5");

var color = d3.scaleOrdinal(d3.schemeCategory10);

var simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(function(d) { return d.id; }).distance(LinkDistance))
    .force("charge", d3.forceManyBody())
    .force("center", d3.forceCenter(width / 2, height / 2));

function LinkDistance(d)
{
	if(d.value == 1) {
        var r = Math.floor(Math.random() * (60 - 20 + 1) + 20);
        return d.value*r+150;
    } else {
        return d.value*40+100;
    }; 
}
    
var div = d3.select("body").append("div").attr("class", "tooltip").style("opacity", 0);

function createGraph (error, graph) {
  if (error) throw error;

  var link = svg.append("g")
      .attr("class", "links")
    .selectAll("line")
    .data(graph.links)
    .enter().append("line")
    .attr("stroke-width", function(d) { return Math.sqrt(d.value); });
  
  var node = svg.append("g")
      .attr("class", "nodes")
    .selectAll("circle")
    .data(graph.nodes)
    .enter().append("circle")
      .attr("r", 5)
      .attr("title", function(d) { return d.id; })
      .attr("fill", function(d) { return color(d.group); })
      .call(d3.drag()
          .on("start", dragstarted)
          .on("drag", dragged)
          .on("end", dragended));

var text = svg.append("g").attr("class", "labels").selectAll("g")
    .data(graph.nodes)
    .enter().append("g");

    text.append("text")
    .attr("x", 14)
    .attr("y", ".31em")
    .attr("class", "nodelabels")
    .style("font-family", "sans-serif")
    .style("font-size", "0.7em")
    .text(function(d) { 
		if(d.group == 1) {return d.name} else {return d.id}; 
	});

    node.on("dblclick",function(d){
        if(d.group == 1) {
          window.location.href = '/files/'+d.id+'/graph/net/';
        }
    });

  simulation
      .nodes(graph.nodes)
      .on("tick", ticked);

  simulation.force("link")
      .links(graph.links);


  function ticked() {
    link
        .attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });
    
    node
        .attr("cx", function(d) { return d.x; })
        .attr("cy", function(d) { return d.y; });

	text
		.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })

    } // ticked

} // createGraph


function dragstarted(d) {
  if (!d3.event.active) simulation.alphaTarget(0.3).restart();
  d.fx = d.x;
  d.fy = d.y;
}

function dragged(d) {
  d.fx = d3.event.x;
  d.fy = d3.event.y;
}

function dragended(d) {
  if (!d3.event.active) simulation.alphaTarget(0);
  d.fx = null;
  d.fy = null;
}

function zoomed() {
  svg.attr("transform", "translate(" + d3.event.transform.x + "," + d3.event.transform.y + ")" + " scale(" + d3.event.transform.k + ")");
}
