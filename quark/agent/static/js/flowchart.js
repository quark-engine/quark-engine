

// 初始化 JSON 物件
let jsonData = {
    nodes: {
        node1: { label: "1. Define the behavior 'Construct Cryptographic Key' in the rule instance." },
        node2: { label: "Define the behavior" },
        node3: { label: "Obtain all instancesss" }
    },
    links: [
        { source: "node1", target: "node2" },
        { source: "node2", target: "node3" }
    ]
};

var flowData = {};
// 測試修改 `links`

// 定義監聽回調函式
function onLinksChange() {
    console.log("Links have changed!");

    // 發送 REST request 至 Flask 伺服器
    fetch('/test', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(jsonData)  // 你可以自定義需要發送的內容
    })
        .then(function (response) {
            return response.json();
        })
        .then(function (responseMessage) {
            var textDiv = document.createElement("div");

            textDiv.className = "message bot";
            textDiv.innerHTML = responseMessage.plain_text + "<br><br>";

            textBox.appendChild(textDiv);

            textBox.scrollTop = textBox.scrollHeight;
        })
        .catch(error => console.error("Error:", error));
}

var nodes = {};

// 創建 JointJS 畫布
const graph = new joint.dia.Graph();
const width = document.getElementById('diagram-container').width;
const paper = new joint.dia.Paper({
    el: document.getElementById('diagram-container'),
    model: graph,
    width: width, height: 815, gridSize: 2,
    // drawGrid: true,
    linkPinning: false,
    // background: {
    //     color: '#f4f4f4'
    // },

    validateConnection: function (cellViewS, magnetS, cellViewT, magnetT, end, linkView) {
        // Prevent linking from output ports to input ports within one element
        return cellViewS !== cellViewT
    },
    validateMagnet: function (cellView, magnet) {
        // Note that this is the default behaviour. It is shown for reference purposes.
        // Disable linking interaction for magnets marked as passive
        return magnet.getAttribute('magnet') !== 'passive';
    },
    snapLinks: { radius: 20 },


    linkDefaults: {
        attrs: {
            line: {
                stroke: 'white',
                strokeWidth: 2
            }
            
        }
    }
});

var paperHeight = paper.getComputedSize().height;
var paperCenterY = (paperHeight / 2) - 25;


let selectedElement = null;
let firstNode = null; // 用于存储连结线的起点

joint.dia.Link.define('standard.Link', {
    router: {
        name: 'orthogonal'
    },
    attrs: {
        line: {
            connection: true,
            stroke: '#fff',
            strokeWidth: 2,
            strokeLinejoin: 'round',
            targetMarker: {
                'type': 'path',
                'd': 'M 10 -5 0 0 10 5 z'
            },
        },
        wrapper: {
            connection: true,
            strokeWidth: 10,
            strokeLinejoin: 'round'
        }
    }
}, {
    markup: [{
        tagName: 'path',
        selector: 'wrapper',
        attributes: {
            'fill': 'none',
            'cursor': 'pointer',
            'stroke': 'transparent'
        }
    }, {
        tagName: 'path',
        selector: 'line',
        attributes: {
            'fill': 'none',
            'pointer-events': 'none'
        }
    }]
});


// Function to add a new node
function addNewNode(nodeId, text, x, y) {

    label = text.length > 20 ? text.slice(0, 20) + '...' : text;

    for (let nodeKey in flowData.nodes) {
        if (flowData.nodes[nodeKey].label === label) {
            console.log(label, "already exists");
            return; // 如果找到重复的 label，返回 true
        }
    }

    var port = {
        attrs: {
            portBody: {
                magnet: true,
                width: 9,
                height: 9,
                x: -4,
                y: -4,
                fill: 'white',
                visibility: 'hidden' // 默认隐藏
            },
            label: {
                text: 'port'
            }
        },
        markup: [{
            tagName: 'rect',
            selector: 'portBody',
        }]
    };

    var portTop = { ...port, position: { name: 'top' }, }
    var portRight = { ...port, position: { name: 'right' }, }
    var portBottom = { ...port, position: { name: 'bottom' }, }
    var portLeft = { ...port, position: { name: 'left' }, }

    var wraptext = joint.util.breakText('yourtext|escapejs', {
        width: 300
    });

    var newNode = new joint.shapes.standard.Rectangle({
        id: nodeId,
        fullText: text,
        position: { x: x, y: y },
        size: { width: 175, height: 50 },
        root: {
            magnet: false
        },
        ports: {
            groups: {
                'top': portTop,
                'right': portRight,
                'bottom': portBottom,
                'left': portLeft
            }
        },
        attrs: {
            text: {
                text: wraptext,
            },
            label: {
                text: label,
                fill: '#FFFFFF',
                fontSize: 16
            },
            body: {
                fill: '#252526',
                stroke: '#FFFFFF',
                strokeWidth: 2,
                rx: 5,
                ry: 5,
                width: 'calc(w)',
                height: 'calc(h)',
            },
        }
    }).addTo(graph);

    newNode.addPorts([
        { group: 'top', },
        { group: 'right', },
        { group: 'bottom', },
        { group: 'left', }
    ]);

    graph.addCell(newNode);

    nodes[nodeId] = newNode;
}

function addLink(sourceNode, targetNode) {

    if (!sourceNode || !targetNode) {
        return;
    }

    const connection = new joint.shapes.standard.Link({ router: { name: 'orthogonal' }, });
    connection.source(sourceNode);
    connection.target(targetNode);
    connection.addTo(graph);

    connection.prop('sourceId', sourceNode.id);
    connection.prop('targetId', targetNode.id);
    connection.attr({
        line: { 
            stroke: '#fff'
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
                    textBox.style.width = "100%";
                }

                // processNodesAndLinks(botMessage.flowdata);

                textBox.scrollTop = textBox.scrollHeight;
            })
            .catch(error => console.error("Error:", error));
        this.remove()
    }
});
var toolsView = new joint.dia.ToolsView({
    tools: [
        removeButton
    ]
});

paper.on('element:mouseover', function(elementView,evt) {

    const fullText = elementView.model.get("fullText")
    // const fullText = 'This is an example of a very long description that exceeds 20 characters';
    // Create a tooltip and append it to the document
    const tooltip = document.createElement('div');
    tooltip.className = '';
    tooltip.textContent = fullText;
    tooltip.style.position = 'absolute';
    tooltip.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
    tooltip.style.color = 'white';
    tooltip.style.padding = '5px';
    tooltip.style.borderRadius = '5px';
    tooltip.style.left = `${evt.clientX + 10}px`;
    tooltip.style.top = `${evt.clientY + 20}px`; 

    document.body.appendChild(tooltip);

    // Remove tooltip on mouseout
    elementView.on('element:mouseout', function() {
        tooltip.remove();
    });
});

paper.on('link:mouseenter', function (linkView) {
    linkView.addTools(toolsView);
});

paper.on('link:mouseleave', function (linkView) {
    linkView.removeTools();
});

paper.on('element:mouseenter', function (element) {
    setPortsVisibility(element, 'visible');
});

paper.on('element:mouseleave', function (element) {
    setPortsVisibility(element, 'hidden');
});

paper.on('link:snap:connect', function (linkView, evt, elementViewConnected, magnet, arrowhead) {

    const sourceId = linkView.model.get('source').id;
    const targetId = linkView.model.get('target').id;

    fetch('/add_link', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            source: sourceId,
            target: targetId
        })
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
                textBox.style.width = "100%";
            }

            // processNodesAndLinks(botMessage.flowdata);

            textBox.scrollTop = textBox.scrollHeight;
        })
        .catch(error => console.error("Error:", error));
})

function setPortsVisibility(element, visibility) {
    element.model.prop('ports/groups/top/attrs/portBody/visibility', visibility)
    element.model.prop('ports/groups/bottom/attrs/portBody/visibility', visibility)
    element.model.prop('ports/groups/left/attrs/portBody/visibility', visibility)
    element.model.prop('ports/groups/right/attrs/portBody/visibility', visibility)
}

graph.on('change', function (cell, opt) {
    if (cell.isLink()) return;
    autosize(cell);
});

function autosize(element) {
    var view = paper.findViewByModel(element);
    var text = view.findBySelector('label')[0];
    if (text) {
        var padding = 50;
        // Use bounding box without transformations so that our auto-sizing works
        // even on e.g. rotated element.
        var bbox = text.getBBox();
        // Give the element some padding on the right/bottom.
        element.resize(bbox.width + padding, bbox.height + padding);
    }
}

async function processNodesAndLinks(flowData) {

    paper.model.clear();
    var paperWidth = paper.getComputedSize().width;
    var nodeCount = Object.keys(flowData.nodes).length;
    var spacing = paperWidth / (nodeCount + 1);
    var i = 1;
    var x = 0;

    const sortedNodes = Object.entries(flowData.nodes).sort(([, a], [, b]) => a.step - b.step);
    const sortedNodesObj = Object.fromEntries(sortedNodes);
    console.log(sortedNodesObj)

    for (const nodeId in sortedNodesObj) {
        const node = flowData.nodes[nodeId];
        posX = (spacing * i) - 75;
        i = i + 1;

        // remove flowdata node
        delete flowData.nodes[nodeId];

        await addNewNode(nodeId, node.label, posX, paperCenterY);
    }
  
    for (const link of flowData.links) {
        let sourceNode = nodes[link.source]
        let targetNode = nodes[link.target]
        await addLink(sourceNode, targetNode);
    }
}

var isComposing = false;


message.addEventListener("compositionstart", function () {
    isComposing = true;
});

message.addEventListener("compositionend", function () {
    isComposing = false;
});

processNodesAndLinks(jsonData);


const buttonContainer = document.getElementById('buttonContainer');

function callButtonContainer(){
    if (buttonContainer.classList.contains('hidden')) {
        buttonContainer.classList.remove('hidden');
        buttonContainer.classList.add('show');
        loadJson();
    } else {
        buttonContainer.classList.remove('show');
        buttonContainer.classList.add('hidden');
    }
}

function callAddNewNode(nodeId, button){
    const buttonText = button.textContent;
    addNewNode(nodeId, buttonText, 2, 3);
}

function loadJson() {
    fetch('/getToolList') // 向 Flask 請求
        .then(response => response.json())
        .then(data => {
            const buttonContainer = document.getElementById('grids');
            buttonContainer.innerHTML = ''; // 清空容器

            // 從 JSON 數據中創建按鈕
            data.QuarkScriptTools.forEach(tool => {
                const button = document.createElement('button');
                button.className = 'grid-button';
                button.innerText = tool.title; // 設定按鈕文字
                button.setAttribute('onclick', 'callAddNewNode('+tool.id+', this)');

                buttonContainer.appendChild(button); // 將按鈕添加到容器中
            });
        })
        .catch(error => console.error('錯誤:', error));
}
