// -*- coding: utf-8 -*-
// This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
// See the file 'LICENSE' for copying permission.

/*global Java, send, rpc*/
function replaceMethodImplementation(targetMethod, classAndMethodName, methodParamTypes, returnType) {
    targetMethod.implementation = function () {
        let callEvent = {
            "type": "CallCaptured",
            "identifier": [classAndMethodName, methodParamTypes, returnType],
            "paramValues": []
        };

        for (const arg of arguments) {
            callEvent["paramValues"].push((arg || "(none)").toString());
        }

        send(JSON.stringify(callEvent));
        return targetMethod.apply(this, arguments);
    };
}

function watchMethodCall(classAndMethodName, methodParamTypes) {
    if (classAndMethodName == null || methodParamTypes == null) {
        return;
    }

    const indexOfLastSeparator = classAndMethodName.lastIndexOf(".");
    const classNamePattern = classAndMethodName.substring(0, indexOfLastSeparator);
    const methodNamePattern = classAndMethodName.substring(indexOfLastSeparator + 1);

    Java.perform(() => {
        const classOfTargetMethod = Java.use(classNamePattern);
        const possibleMethods = classOfTargetMethod[`${methodNamePattern}`];

        if (typeof possibleMethods === "undefined") {
            const failedToWatchEvent = {
                "type": "FailedToWatch",
                "identifier": [classAndMethodName, methodParamTypes]
            };

            send(JSON.stringify(failedToWatchEvent));
            return;
        }

        possibleMethods.overloads.filter((possibleMethod) => {
            const paramTypesOfPossibleMethod = possibleMethod.argumentTypes.map((argument) => argument.className);
            return paramTypesOfPossibleMethod.join(",") === methodParamTypes;
        }).forEach((matchedMethod) => {
            const retType = matchedMethod.returnType.name;
            replaceMethodImplementation(matchedMethod, classAndMethodName, methodParamTypes, retType);
        }
        );

    });
}

rpc.exports["watchMethodCall"] = (classAndMethodName, methodParamTypes) => watchMethodCall(classAndMethodName, methodParamTypes);