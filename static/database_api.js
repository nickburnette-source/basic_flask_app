function getData(endpoint='../ui/') {
    let requestURL = endpoint;
    let request = new XMLHttpRequest();
    request.open('GET', requestURL, false);
    // request.responseType = 'json';
    // request.timeout = 3000;
    // request.ontimeout = function (e) {
    //     alert('Request Timed Out!');
    // };
    request.send();
    return JSON.parse(request.response)
    // request.onload = function () {
    //    New way for if async
    // }
}


function setVAR(url, variable) {
    let requestURL = url + variable;
    let request = new XMLHttpRequest();
    request.open('POST', requestURL, true);
    request.send();
}


