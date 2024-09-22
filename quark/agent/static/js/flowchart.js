// 初始化 JSON 物件
let jsonData = {
    nodes: {
        node1: { label: "Define the behavior 'Construct Cryptographic Key' in the rule instance." },
        node2: { label: "run Quark Analysis using the rule instance on the APK sample." },
        node3: { label: "Obtain all instancesss" },
        node4: { label: "Check if the parameter values are hard-coded." },
        node5: { label: "Write the code in the specified file." }
    },
    links: [
        { source: "node1", target: "node2" },
        { source: "node2", target: "node3" },
        { source: "node3", target: "node4" },
        { source: "node4", target: "node5" }
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
    width: "100%", height: "93%",
    drawGrid: true,
    gridSize: 10,
    linkPinning: false,
    background: {
        color: 'rgba(128, 128, 128, 0.4)' // 灰色 (RGB 128,128,128) 且透明度 40%
    },

    validateConnection: function (cellViewS, magnetS, cellViewT, magnetT, end, linkView) {
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

paper.setGrid({ name: 'mesh', args: { color: 'hsla(212, 7%, 50%, 0.5)' } });

var paperHeight = paper.getComputedSize().height;
var paperCenterY = (paperHeight / 2) - 25;

var papaerWidth = paper.getComputedSize().width;
var paperCenterX = (papaerWidth / 2) - 75;

let selectedElement = null;
let firstNode = null; // 用于存储连结线的起点

joint.dia.Link.define('standard.Link', {
    router: {
        name: 'manhattan'
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


var toolsView = new joint.dia.ToolsView({
    tools: [
        removeButton
    ]
});


// paper.on('element:pointerclick', function (elementView, evt) {
//     console.log(elementView, evt)
//     // elementView.model.attr('label/text', 'test')
//     elementView.model.size({height: 200})
// });

paper.on('element:mouseenter', function (elementView, evt) {

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
    elementView.on('element:mouseout', function () {
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
    console.log(sourceId, targetId)

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
            }
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

    // paper.model.clear();
    var paperWidth = paper.getComputedSize().width;
    var nodeCount = Object.keys(flowData.nodes).length;
    var spacing = 50 + paperHeight / 10;
    var i = 1;
    var x = 0;

    const sortedNodes = Object.entries(flowData.nodes).sort(([, a], [, b]) => a.no - b.no);
    const sortedNodesObj = Object.fromEntries(sortedNodes);

    for (const nodeId in sortedNodesObj) {
        const node = flowData.nodes[nodeId];
        posY = (spacing * i) - 20;
        posX = (spacing+200 * i) - 300;
        i = i + 1;

        // remove flowdata node
        // delete flowData.nodes[nodeId];

        await addNewNode(nodeId, node.label, posX, posY);
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

const buttonContainer = document.getElementById('buttonContainer');
const button = document.getElementById('new-action-button');

function callButtonContainer() {
    if (buttonContainer.classList.contains('hidden')) {
        buttonContainer.classList.remove('hidden');
        buttonContainer.classList.add('show');
        loadJson();
        button.textContent = "-";
    } else {
        buttonContainer.classList.remove('show');
        buttonContainer.classList.add('hidden');
        button.textContent = "+";
    }
}

function callAddNewNode(nodeId, title, description) {

    newNode = addNewNode(nodeId, title, 2, 3);
    fetch('/add_analyze_step', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            node: description,
            nodeId: newNode.id
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
            }

            textBox.scrollTop = textBox.scrollHeight;
        })
        .catch(error => console.error("Error:", error));
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
                button.setAttribute('onclick', 'callAddNewNode(' + tool.id + ', "' + tool.title + '", "' + tool.description + '")');

                buttonContainer.appendChild(button); // 將按鈕添加到容器中
            });
        })
        .catch(error => console.error('錯誤:', error));
}



// processNodesAndLinks(jsonData);


// const Form = joint.dia.Element.define('example.form', {
//     attrs: {
//         foreignObject: {
//             width: 'calc(w)',
//             height: 'calc(h)'
//         }
//     }
// }, {
//     markup: joint.util.svg/* xml */`
//             <foreignObject @selector="foreignObject">
//             <div xmlns="http://www.w3.org/1999/xhtml" class="outer" >
//                 <div class="inner">
//                 <text @selector="fff" x="20" y="35" class="small">My</text>

//                         <input @selector="name" type="text" name="name" autocomplete="off" placeholder="Your diagram name"/>
//                         <button onclick="tttttt('fuck')">
//                             <span>Submit</span>
//                         </button>

//                 </div>
//             </div>
//         </foreignObject>
//         `
// });



const Form = joint.dia.Element.define('example.form', {
    attrs: {
        foreignObject: {
            width: 'calc(w)',
            height: 'calc(h)'
        },
        card: {
            class: 'card'
        }
    }
}, {
    markup: joint.util.svg/* xml */`
    <foreignObject @selector="foreignObject">
        <div xmlns="http://www.w3.org/1999/xhtml" class="outer" >

            <div @selector="card" class="card">
                <text class="card-title">fff</text>
                <button class="expand-button" onclick="expandCard(this)">+</button>
                <div class="card-content">
                    <label class="card-label">Edit Quark detection rules (Edit behavior)</label>
                    <label class="card-label">First API of behavior</label>
                    <input type="text" name="name" autocomplete="off" placeholder="Input API full name"/>
                    <label class="card-label">Second API of behavior</label>
                    <input type="text" name="name" autocomplete="off" placeholder="Input API full name"/>
                    <button>Save</button>
                </div>
            </div>

        </div>
    </foreignObject>
        `
});

const FormView = joint.dia.ElementView.extend({

});


paper.on('element:mouseenter', (elementView, evt) => {
    elementView.model.toFront();
});

var highestZIndex = 1;
function expandCard(button) {
    const card = button.parentElement;
    if (card.classList.contains('expanded')) {
        card.classList.remove('expanded');
    } else {
        card.classList.add('expanded');
        highestZIndex++;
        card.style.zIndex = highestZIndex+1;

    }
}
// paper.on('element:pointerclick', function (elementView, evt) {
//     console.log("fick")
//     const cardClass = elementView.model.attr('card/class');
//     // console.log(cardClass)
//     // elementView.model.attr('card/class', 'card expanded');

//     if (cardClass === 'card expanded') {
//         elementView.model.attr('card/class', 'card');
//     } else {
//         elementView.model.attr('card/class', 'card expanded');
//     }
// })

