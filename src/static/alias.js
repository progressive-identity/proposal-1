var Alias = {};

Alias._urlencode = function(args) {
    var r = [];
    for (k in args) {
        var v = args[k];

        r.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    }
    return r.join('&');
}


