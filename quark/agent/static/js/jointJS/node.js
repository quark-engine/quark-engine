const nodeWidth = 300;
const nodeHeight = 50;
const wrapTextWidth = 20;

const behaviorNode = joint.dia.Element.define('example.form', {
    attrs: {
        foreignObject: {
            width: 'calc(w)',
            height: 'calc(h)'
        },
        card: {
            class: 'card'
        },
        cardTitle: {
            class: 'card-title',
            html: ''
        }
    }
}, {
    markup: joint.util.svg/* xml */`
    <foreignObject @selector="foreignObject">
        <div xmlns="http://www.w3.org/1999/xhtml" class="outer" >

            <div @selector="card" class="card">
                <text @selector="cardTitle" class="card-title">fff</text>
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

function addNewNode(nodeId, text, x, y) {

    //Check if node already exists
    for (let cell in graph.getCells()) {
        if (cell.fullText === text) {
            console.log(label, "already exists");
            return; // 如果找到重复的 label，返回 true
        }
    }

    label = text.length > wrapTextWidth ? text.slice(0, wrapTextWidth) + '...' : text;

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
                y: -204,
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

    var portTop = {
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
        }],
        position: { name: 'top' },
    };

    var portRight = { ...port, position: { name: 'right' }, }
    // var portBottom = { ...port, position: { name: 'bottom' }, }
    var portLeft = { ...port, position: { name: 'left' }, }


    var wraptext = joint.util.breakText('yourtext|escapejs', {
        width: nodeWidth
    });

    // var newNode = new joint.shapes.standard.Rectangle({
    //     id: nodeId,
    //     fullText: text,
    //     position: { x: x, y: y },
    //     size: { width: nodeWidth, height: nodeHeight },
    //     root: {
    //         magnet: false
    //     },
    //     ports: {
    //         groups: {
    //             'top': portTop,
    //             'right': portRight,
    //             'bottom': portBottom,
    //             'left': portLeft
    //         }
    //     },
    //     attrs: {

    //         text: {
    //             text: wraptext,
    //         },
    //         label: {
    //             text: label,
    //             fill: '#FFFFFF',
    //             fontSize: 16,   
    //             // refX: '-15%',
    //         },
    //         body: {
    //             filter: {
    //                 name: 'dropShadow',
    //                 args: {
    //                     dx: 2,
    //                     dy: 2,
    //                     blur: 5,
    //                     color: 'rgba(10,10,10,0.2)'
    //                 }
    //             },
    //             fill: '#252526',
    //             stroke: null,
    //             rx: 5,
    //             ry: 5,
    //             width: 'calc(w)',
    //             height: 'calc(h)',
    //         },
    //     }

    // }).addTo(graph);


    var newNode = new behaviorNode({
        id: nodeId,
        fullText: text,
        position: { x: x, y: y },
        size: { width: 300, height: 450 },
        root: {
            magnet: "passive"
        },
        ports: {
            groups: {
                'top': portTop,
                'right': portRight,
                'left': portLeft
            }
        },
        attrs: {
            cardTitle: {
                html: label
            }
        }
    }).addTo(graph);

    newNode.addPorts([
        { group: 'top', },
        { group: 'right', },
        { group: 'left', }
    ]);


    graph.addCell(newNode);

    nodes[nodeId] = newNode;
    return newNode;
};