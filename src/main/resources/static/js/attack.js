var interface = [];

function init() {
    //输入限制
    $('.srcIp').attr('maxlength', '3');
    $('.srcIp').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value>255)value=255;if(value<0)value=0');

    $('.desIp').attr('maxlength', '3');
    $('.desIp').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value>255)value=255;if(value<0)value=0');

    $('.srcMac').attr('maxlength', '2');
    $('.srcMac').attr('oninput', 'value=value.replace(/[^\\w\\.\\/]/ig,\'\')');

    $('.desMac').attr('maxlength', '2');
    $('.desMac').attr('oninput', 'value=value.replace(/[^\\w\\.\\/]/ig,\'\')');

    $('.srcPort').attr('maxlength','5');
    $('.srcPort').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value>65535)value=65535;if(value<0)value=0');

    $('.desPort').attr('maxlength','5');
    $('.desPort').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value>65535)value=65535;if(value<0)value=0');

    $('#round').attr('maxlength', '3');
    $('#round').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value<1)value=1');

    $('#speed').attr('maxlength', '3');
    $('#speed').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value<1)value=1');

    $('#sleep').attr('maxlength', '5');
    $('#sleep').attr('oninput', 'value=value.replace(/[^\\d]/g,\'\');if(value<0)value=0');

    getNetworkInterface(function (data) {
        interface = data.data;
        var htmlstr = '';
        for (var i = 0; i < interface.length; i++) {
            htmlstr += `<option value="${i}">${interface[i].description}</option>`;
        }
        $('#interface').append(htmlstr);


    });


    $('#packetType').change(function () {
        switch (parseInt($('#packetType option:selected').val())) {
            case 1:
                $('#desMac').css('display', 'none');
                $('#srcPort').css('display', 'none');
                $('#desPort').css('display', 'none');
                $('#len').css('display', 'none');
                break;
            case 2:
                $('#desMac').css('display', 'block');
                $('#srcPort').css('display', 'none');
                $('#desPort').css('display', 'none');
                $('#len').css('display', 'none');
                break;
            case 3:
                $('#desMac').css('display', 'block');
                $('#srcPort').css('display', 'none');
                $('#desPort').css('display', 'none');
                $('#len').css('display', 'block');
                break;
            case 4:
                $('#desMac').css('display', 'block');
                $('#srcPort').css('display', 'none');
                $('#desPort').css('display', 'none');
                $('#len').css('display', 'none');
                break;
            case 5:
                $('#desMac').css('display', 'block');
                $('#srcPort').css('display', 'block');
                $('#desPort').css('display', 'block');
                $('#len').css('display', 'none');
                break;
            case 6:
                $('#desMac').css('display', 'block');
                $('#srcPort').css('display', 'block');
                $('#desPort').css('display', 'block');
                $('#len').css('display', 'none');
                break;
        }
    });

    $('#submit').click(function () {

        switch (parseInt($('#packetType option:selected').val())) {
            case 1:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 1,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp()
                });
                break;
            case 2:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 2,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp(),
                    desMac: getDesMac()
                });
                break;
            case 3:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 3,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp(),
                    desMac: getDesMac()
                });
                break;
            case 4:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 4,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp(),
                    desMac: getDesMac()
                });
                break;
            case 5:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 5,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp(),
                    desMac: getDesMac(),
                    srcPort:getSrcPort(),
                    desPort:getDesPort()
                });
                break;
            case 6:
                submit({
                    index: parseInt($('#interface option:selected').val()),
                    type: 6,
                    round: getRound(),
                    speed: getSpeed(),
                    sleep: getSleep(),
                    srcIp: getSrcIp(),
                    srcMac: getSrcMac(),
                    desIp: getDesIp(),
                    desMac: getDesMac(),
                    srcPort:getSrcPort(),
                    desPort:getDesPort()
                });
                break;
        }

    });
}

function getSrcIp() {
    var srcIp = '';
    var srcIpIn = $('.srcIp');
    var temp;
    for (var i = 0; i < srcIpIn.length - 1; i++) {
        temp = srcIpIn.eq(i).val();
        if (temp == '') {
            temp = '0';
        }
        srcIp += temp + '.';
    }
    temp = srcIpIn.eq(srcIpIn.length - 1).val();
    if (temp == '') {
        temp = '0';
    }
    srcIp += temp;
    return srcIp;
}

function getDesIp() {
    var desIp = '';
    var temp = '';
    var desIpIn = $('.desIp');
    for (var i = 0; i < desIpIn.length - 1; i++) {
        temp = desIpIn.eq(i).val();
        if (temp == '') {
            temp = '0';
        }
        desIp += temp + '.';
    }
    temp = desIpIn.eq(desIpIn.length - 1).val();
    if (temp == '') {
        temp = '0';
    }
    desIp += temp;
    return desIp;
}

function getSrcMac() {
    var srcMac = '';
    var temp = '';
    var srcMacIn = $('.srcMac');
    for (var i = 0; i < srcMacIn.length - 1; i++) {
        temp = srcMacIn.eq(i).val();
        if (temp == '') {
            temp = '0';
        }
        srcMac += temp + '-';
    }
    temp = srcMacIn.eq(srcMacIn.length - 1).val();
    if (temp == '') {
        temp = '0';
    }
    srcMac += temp;
    return srcMac;
}

function getDesMac() {
    var desMac = '';
    var temp = '';
    var desMacIn = $('.desMac');
    for (var i = 0; i < desMacIn.length - 1; i++) {
        temp = desMacIn.eq(i).val();
        if (temp == '') {
            temp = '0';
        }
        desMac += temp + '-';
    }
    temp = desMacIn.eq(desMacIn.length - 1).val();
    if (temp == '') {
        temp = '0';
    }
    desMac += temp;
    return desMac;
}

function getSrcPort() {
    var port=$('.srcPort').eq(0).val();
    if(port==''){
        port=0;
    }
    return port;
}

function getDesPort() {
    var port=$('.desPort').eq(0).val();
    if(port==''){
        port=0;
    }
    return port;
}

function getRound() {
    var round = $('#round').val();
    if (round == '')
        round = '1';
    return round;
}

function getSpeed() {
    var speed = $('#speed').val();
    if (speed == '')
        speed = '1';
    return speed;
}

function getSleep() {
    var sleep = $('#sleep').val();
    if (sleep == '')
        sleep = '1';
    return sleep;
}

init();