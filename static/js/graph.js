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
    .force("link", d3.forceLink().id(function(d) { return d.id; }).distance(linkDistance))
    .force("charge", d3.forceManyBody())
    .force("center", d3.forceCenter(width / 2, height / 2));

function linkDistance(d) {
    return ((d.label-102)*2)*-8;
}

var div = d3.select("body").append("div").attr("class", "tooltip").style("opacity", 0);

function createGraph (error, graph, showFilenames) {
  if (error) throw error;

  var link = svg.append("g")
      .attr("class", "links")
    .selectAll("line")
    .data(graph.links)
    .enter().append("line")
      .attr("stroke", function(d) { return color(d.group); })
      .attr("marker-end", "url(#arrow)");

  
  var linkText = svg.append("g").attr("class", "link-label").selectAll("links")
    .data(graph.links)
    .enter().append("g");

    linkText.append("text")
    .attr("text-anchor", "middle")
    .text(function(d) { return d.label; });

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

 if(showFilenames) { 
    var text = svg.append("g").attr("class", "labels").selectAll("g")
    .data(graph.nodes)
    .enter().append("g");

    text.append("text")
    .attr("x", 14)
    .attr("y", ".31em")
    .attr("class", "nodelabels")
    .style("font-family", "sans-serif")
    .style("font-size", "0.7em")
	.style("opacity", 0)
    .text(function(d) { return d.filename; });

    text.append("text")
        .attr("x", 14)
        .attr("y", ".31em")
        .attr("class", "nodetags")
        .style("font-family", "sans-serif")
        .style("font-size", "0.9em")
	    .style("opacity", 0)
        .text(function(d) {
            if(d.tags) { return d.tags;} else {return null;} 
        });
  }

  node.on("dblclick",function(d){
    window.location.href = '/files/'+d.id+'/view';
  });

  node.on("mouseover", function(d) {
      div.transition()
          .duration(200)
          .style("opacity", .9);
      div.html(d.filename + "<br/>" + d.name + "<br/>")
          .style("left", (d3.event.pageX - 1) + "px")
          .style("top", (d3.event.pageY - 35) + "px");
  });
  node.on("mouseout", function(d) {
      div.transition()
          .duration(500)
          .style("opacity", 0);
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
    
    linkText
        .attr("transform", function(d) {
	        if (d.target.x > d.source.x) { return "translate("+(d.source.x + (d.target.x - d.source.x)/2)+","+(d.source.y + (d.target.y - d.source.y)/2)+")"; }
	        else { return "translate("+(d.target.x + (d.source.x - d.target.x)/2)+","+(d.target.y + (d.source.y - d.target.y)/2)+")"; }
	    })


    node
        .attr("cx", function(d) { return d.x; })
        .attr("cy", function(d) { return d.y; });

    if(showFilenames) {
        text
            .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
    }

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



