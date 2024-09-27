
function addLink(sourceNode, targetNode) {

    if (!sourceNode || !targetNode) {
        return;
    }

    // Check if paper have same connection
    for (const link of graph.getLinks()) {
        console.log(link.source().id, link.target().id)
        if (link.source().id === sourceNode.id && link.target().id === targetNode.id) {
            return;
        }
    }

    const connection = new joint.shapes.standard.Link({
        router: { name: 'manhattan', args: { step: 50,} },
        connector: { name: 'rounded', args: { radius: 50, }, },
    });
    
    const sourceTopPort = sourceNode.getGroupPorts('top')[0].id
    const sourceRightPort = sourceNode.getGroupPorts('right')[0].id
    const sourceLeftPort = sourceNode.getGroupPorts('left')[0].id

    const targetTopPort = targetNode.getGroupPorts('top')[0].id
    const targetRightPort = targetNode.getGroupPorts('right')[0].id
    const targetLeftPort = targetNode.getGroupPorts('left')[0].id

    connection.source(sourceNode, {"port": sourceRightPort});
    //connection.target(targetNode, {"port": targetTopPort});
    connection.target(targetNode, {"port": targetTopPort});
    // Check if paper have same connection
    connection.addTo(graph);

    connection.prop('sourceId', sourceNode.id);
    connection.prop('targetId', targetNode.id);
    connection.attr({
        line: {
            stroke: '#fff',
        }
    });
}

var removeButton = new joint.linkTools.Remove({
    action: function (evt) {
        // a link was removed  (cell.id contains the ID of the removed link)
        const sourceId = this.model.get('source').id;
        const targetId = this.model.get('target').id;

        // 發送 REST request 至 Flask 伺服器
        fetch('/remove_link', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                source: sourceId,
                target: targetId
            })  // 你可以自定義需要發送的內容
        })
            .then(function (response) {
                return response.json();
            })
            .then(function (botMessage) {
                console.log(botMessage)
                var textDiv = document.createElement("div");

                textDiv.className = "message bot";
                textDiv.innerHTML = DOMPurify.sanitize(marked.parse(botMessage.plain_text)); // eslint-disable-line

                textBox.appendChild(textDiv);

                if (botMessage.code_blocks.length > 0) {
                    codeBox.style.display = "block";
                    textBox.style.width = "49%";
                    var codeLines = botMessage.code_blocks.join("\n").split("\n").slice(1).join("\n");
                    codeMirror.setValue(codeLines);
                    codeMirror.setOption("mode", detectLanguage(botMessage.code_blocks.join("\n\n\n")));
                } else {
                    codeBox.style.display = "none";

                }

                textBox.scrollTop = textBox.scrollHeight;
            })
            .catch(error => console.error("Error:", error));
        this.remove()
    }
});
