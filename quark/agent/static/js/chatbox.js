/*global CodeMirror*/
/*global marked*/
/*global DOMPurify*/

var textBox = document.getElementById("textBox");
var codeBox = document.getElementById("codeBox");
var message = document.getElementById("message");
var send = document.getElementById("send");
var copyButton = document.getElementById("copyButton");
var languageLabel = document.getElementById("languageLabel");

// Initialize CodeMirror with dark theme
var codeMirror = new CodeMirror(codeBox, {
  lineNumbers: true,
  theme: "dracula",
  readOnly: false,
  backgroundColor: "#fff",
});

function detectLanguage(code) {
  const patterns = {
    xml: /^\s*<!DOCTYPE html>|<html/,
    clike: /^\s*#include|int\s+main\s*\(/,
    python: /^\s*def\s+|import\s/,
    javascript: /^\s*(function|var|let|const)\s+/.test(code) || /console\.log/.test(code)
  };

  for (const [language, pattern] of Object.entries(patterns)) {
    if (pattern.test(code)) {
      return language;
    }
  }

  return "plaintext";
}

codeMirror.on("change", function (instance) {
  var code = instance.getValue();
  var detectedLanguage = detectLanguage(code);
  instance.setOption("mode", detectedLanguage);
});

send.addEventListener("click", function () {
  var userMessage = DOMPurify.sanitize(message.value);
  var userDiv = document.createElement("div");

  userDiv.className = "message user";
  userDiv.innerHTML = marked.parse(userMessage);

  textBox.appendChild(userDiv);

  message.value = "";

  fetch("/get_response?message=" + encodeURIComponent(userMessage))
    .then(function (response) {
      return response.json();
    })
    .then(function (botMessage) {
      var textDiv = document.createElement("div");

      textDiv.className = "message bot";
      textDiv.innerHTML = marked.parse(DOMPurify.sanitize(botMessage.plain_text));

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

      textBox.scrollTop = textBox.scrollHeight;
    });
});

var isComposing = false;


message.addEventListener("compositionstart", function () {
  isComposing = true;
});

message.addEventListener("compositionend", function () {
  isComposing = false;
});


message.addEventListener("keydown", function (event) {
  const keyCode = event.which || event.keyCode;
  if (keyCode === 13 && !event.shiftKey) {
    event.preventDefault();
    send.click();
  }
});
