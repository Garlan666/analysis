var ifFresh = false;           //是否每秒刷新
var totalPacketNum = 0;        //总数据包数量
var PacketNumPS = 0;           //每秒数据包数量
var PacketPerSecondChart;      //每秒数据包数量图表
var PacketPerSecondData = [];  //每秒数据包数量数组
var PacketTotalChart;          //总数据包数量图表
var PacketTotalData = [];      //总数据包数量数组
var PacketKindChart;           //数据包数量比例图表
var totalPacketLen = 0;          //总数据包大小
var PacketLenPS = 0;             //每秒数据包大小
var PacketLenPSChart;          //每秒数据包大小图表
var PacketLenPSData = [];        //每秒数据包大小数组
var PacketTotalLenChart;       //总数据包大小图表
var PacketTotalLenData = [];     //总数据包大小数组
var PacketKindLenChart;        //数据包大小比例图表
var interfaceList = [];        //网卡接口及状态列表
var interfaceIndex = -1;       //当前网卡索引
var warningList = [];
var warningLen = 0;


var div = document.getElementById('warn-list');

function init() {
    getNetworkInterface(function (data) {
        interfaceList = data.data;
        if (interfaceList.length > 0) {
            $('#Tabs').empty();
            for (var i = 0; i < interfaceList.length; i++) {
                $('#Tabs').append(`<li><a id="${i}">网卡${parseInt(i + 1)}</a></li>`);
            }
            $(".tabs li").width('' + 1000 / interfaceList.length + 'px');
            var tabs = $(".tabs li a");

            tabs.click(function () {
                var id = this.id;
                tabs.removeClass("active");
                $(this).addClass("active");
                $('#instruction').fadeOut(200);
                setTimeout(function () {
                    $('#instruction').empty();
                    $('#instruction').append(`
                <div><span>描述：${interfaceList[id].description}</span></div>
                <div><span>名称：${interfaceList[id].name}</span></div>
                <div><span>链路：${interfaceList[id].datalink_description +'&nbsp;&nbsp;'+ interfaceList[id].datalink_name}</span></div>
                <div><span>地址：</br>${interfaceList[id].address}</span></div>
                `);
                }, 200)
                $('#instruction').fadeIn(300);

                if (ifFresh) {
                    if (interfaceList[this.id].on) {
                        $('#start').attr('disabled', true);
                        $('#end').attr('disabled', false);
                        $('#blance').attr('disabled', true);
                    } else {
                        $('#start').attr('disabled', true);
                        $('#end').attr('disabled', true);
                        $('#blance').attr('disabled', true);
                    }
                } else {
                    $('#start').attr('disabled', false);
                    $('#end').attr('disabled', true);
                    $('#blance').attr('disabled', false);
                }

                if (interfaceList[this.id].promisc) {
                    $('#blance').prop('checked', true);
                } else {
                    $('#blance').prop('checked', false);
                }

            });


            for (var i = 0; i < interfaceList.length; i++) {
                if (interfaceList[i].on) {
                    interfaceIndex = i;
                    ifFresh = true;
                    tabs.eq(i).click();
                    refresh();
                    getWarning();
                    break;
                }
            }

            if (!ifFresh) {
                tabs.eq(0).click();
            }


        }
    });

    $('#start').on('click', function () {
        var index = $('.active').eq(0).attr('id');
        if (interfaceList[index].on) {
            ifFresh = true;
            refresh();
            getWarning();
        } else {
            startCatch(index);
        }

    });

    $('#end').on('click', function () {
        var index = $('.active').eq(0).attr('id');
        stopCatch(index);
    });


    $('#blance').change(function () {
        if ($('#blance').prop('checked')) {
            if (interfaceList.length > 0) {
                var index = $('.active').eq(0).attr('id');
                interfaceList[index].promisc = true;
            }
        } else {
            if (interfaceList.length > 0) {
                var index = $('.active').eq(0).attr('id');
                interfaceList[index].promisc = false;
            }
        }
    });


    //图表初始化
    PacketPerSecondChart = echarts.init(document.getElementById('chart1'));
    PacketPerSecondChart.setOption(chartOption1(PacketPerSecondData));

    PacketLenPSChart = echarts.init(document.getElementById('chart2'));
    PacketLenPSChart.setOption(chartOption2(PacketLenPSData));

    PacketTotalChart = echarts.init(document.getElementById('chart3'));
    PacketTotalChart.setOption(chartOption3(PacketTotalData));

    PacketTotalLenChart = echarts.init(document.getElementById('chart4'));
    PacketTotalLenChart.setOption(chartOption4(PacketTotalLenData));

    PacketKindChart = echarts.init(document.getElementById('chart5'));
    PacketKindChart.setOption(chartOption5());

    PacketKindLenChart = echarts.init(document.getElementById('chart6'));
    PacketKindLenChart.setOption(chartOption6());

}

function startCatch(index) {
    startCatchPacket({index: index, promisc: interfaceList[index].promisc}, function (data) {
        if (data.code == 100) {
            toastr.success('开始');
            if (interfaceIndex != -1 && interfaceIndex != index) {
                clean();
            }
            clean();
            interfaceIndex = index;
            interfaceList[index].on = true;
            ifFresh = true;
            $('#start').attr('disabled', true);
            $('#end').attr('disabled', false);
            $('#blance').attr('disabled', true);
            refresh();
            getWarning();
        } else {
            toastr.error('错误');
        }
    });
}

function stopCatch(index) {
    stopCatchPacket({index: index}, function (data) {
        if (data.code == 100) {
            ifFresh = false;
            $('#start').attr('disabled', false);
            $('#end').attr('disabled', true);
            $('#blance').attr('disabled', false);
            interfaceList[index].on = false;
        } else {
            toastr.error('错误');
        }
    });
}


function clean() {
    PacketPerSecondData = [];
    PacketTotalData = [];
    totalPacketNum = 0;
    PacketNumPS = 0;
    PacketLenPSData = [];
    PacketTotalLenData = [];
    totalPacketLen = 0;
    PacketLenPS = 0;
    warningList = [];
    warningLen = 0;
}

function filterNum(num) {
    if (num < 10) {
        return "0" + num;
    } else {
        return num;
    }
}

function getWarning() {
    if (ifFresh) {
        getWarningList(warningLen, function (data) {
            if (data.code == 100) {
                warningList = data.data;
                console.log(warningList);
                showWarning();
            }
        });
        setTimeout(getWarning, 5000);
    }
}

function showWarning() {
    for (var i = 0; i < warningList.length; i++) {
        var time = new Date(warningList[i].packet.sec * 1000);
        var ptime = time.getFullYear() + "-" + filterNum(time.getMonth() + 1) + "-" + filterNum(time.getDate()) + " "
            + filterNum(time.getHours()) + ":" + filterNum(time.getMinutes()) + ":" + filterNum(time.getSeconds());

        switch (warningList[i].protocol) {
            case 1:
                ;
                break;
            case 2:
                ;
                break;
            case 3:
                showICMP(warningList[i], ptime);
                break;
            case 4:
                showARP(warningList[i], ptime);
                break;
        }

        div.scrollTop = div.scrollHeight;

    }
    warningLen += warningList.length;
}

function showTCP(wp, ptime) {

    var pro = 'TCP';
    var htmlstr = '';
}

function showUDP(wp, ptime) {

    var pro = 'UDP';
    var htmlstr = '';
}

function showICMP(wp, ptime) {

    var pro = 'ICMP';
    var htmlstr = '';

    switch (wp.packet.type) {
        case 0:
            pro += '  &nbsp;ping应答';
            break;
        case 8:
            pro += '  &nbsp;ping请求';
            break;
    }

    $('#warn-list').append(`<div class="one-warn">
            <div>
                类型：<span>${pro}</span>
            </div>
            <div>
                时间：<span>${ptime}</span>
            </div>
            <div>
                 源地址：<span>${wp.packet.src_ip}</span>  &nbsp;&nbsp;目的地址：<span>${wp.packet.dst_ip}</span>
            </div>
            <div>
                 <span>seq=${wp.packet.seq}   &nbsp;&nbsp;TTL=${wp.packet.hop_limit}</span>
            </div>
            ${htmlstr}
            <div>警告信息：<span>${wp.warningMsg}</span></div>
        </div>`);
}

function showARP(wp, ptime) {
    var pro;
    var htmlstr;
    switch (wp.packet.operation) {
        case 1:
            pro = 'ARP请求';
            htmlstr = `<div>
                     <span>Who has ${wp.packet.targetProtocolAddress}? Tell ${wp.packet.senderProtocolAddress}</span>
                     </div>`;
            break;
        case 2:
            pro = 'ARP响应';
            htmlstr = `<div>
                     <span>${wp.packet.senderProtocolAddress} is at ${wp.packet.senderHardwareAddress}</span>
                     </div>`;
            break;
        case 3:
            pro = 'RARP请求';
            break;
        case 4:
            pro = 'RARP响应';
            break;
    }

    $('#warn-list').append(`<div class="one-warn">
            <div>
                类型：<span>${pro}</span>
            </div>
            <div>
                时间：<span>${ptime}</span>
            </div>
            <div>
                 源地址：<span>${wp.packet.senderHardwareAddress+'/'+wp.packet.senderProtocolAddress}</span>  
                 &nbsp;&nbsp;目的地址：<span>${wp.packet.targetHardwareAddress+'/'+wp.packet.targetProtocolAddress}</span>
            </div>
            ${htmlstr}
            <div>警告信息：<span>${wp.warningMsg}</span></div>
        </div>`);
}


function lenFormatter(data) {
    var value = '';
    if (data <= 0) {
        value = '0B';
    } else {
        var k = 1024;
        data = data * k;
        var sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        var c = Math.floor(Math.log(data) / Math.log(k));
        value = (data / Math.pow(k, c)).toFixed(2) + ' ' + sizes[c];
    }
    return value;
}


function refresh() {
    if (ifFresh) {
        reFresh(function (data) {
            var packetInfo = data.data;
            console.log(packetInfo);


            var totalNum = parseInt(packetInfo.total);
            var totalLen = parseFloat(packetInfo.lenTotal);


            if (totalPacketNum != 0) {
                PacketNumPS = totalNum - totalPacketNum;
            }
            totalPacketNum = totalNum;


            if (totalPacketLen != 0) {
                PacketLenPS = totalLen - totalPacketLen;
            }
            totalPacketLen = totalLen;


            now = new Date();
            PacketPerSecondData.push({
                name: now.toString(),
                value: [
                    now.getTime(),
                    PacketNumPS
                ]
            });

            PacketLenPSData.push({
                name: now.toString(),
                value: [
                    now.getTime(),
                    PacketLenPS
                ]
            });

            PacketTotalData.push({
                name: now.toString(),
                value: [
                    now.getTime(),
                    PacketNumPS
                ]
            });

            PacketTotalLenData.push({
                name: now.toString(),
                value: [
                    now.getTime(),
                    PacketLenPS
                ]
            });

            if (PacketPerSecondData.length > 30) {
                PacketPerSecondData.shift();
                PacketLenPSData.shift();
            }


            PacketPerSecondChart.setOption({
                title: {
                    text: '每秒数据包数量：' + PacketNumPS
                },
                series: [{
                    data: PacketPerSecondData
                }]
            });

            PacketLenPSChart.setOption({
                title: {
                    text: '每秒数据包大小：' + lenFormatter(PacketLenPS) + '/s'
                },
                series: [{
                    data: PacketLenPSData
                }]
            });

            PacketTotalChart.setOption({
                title: {
                    text: '数据包总数：' + totalPacketNum
                },
                series: [{
                    data: PacketTotalData
                }]
            });

            PacketTotalLenChart.setOption({
                title: {
                    text: '数据包总大小：' + lenFormatter(totalPacketLen)
                },
                series: [{
                    data: PacketTotalLenData
                }]
            });

            PacketKindChart.setOption({
                series: [{
                    data: [
                        {value: packetInfo.kind[0], name: 'TCP'},
                        {value: packetInfo.kind[1], name: 'UDP'},
                        {value: packetInfo.total - packetInfo.kind[0] - packetInfo.kind[1], name: '其他'}
                    ]
                }]
            });

            PacketKindLenChart.setOption({
                series: [{
                    data: [
                        {value: parseFloat(packetInfo.lenKind[0]).toFixed(2), name: 'TCP'},
                        {value: parseFloat(packetInfo.lenKind[1]).toFixed(2), name: 'UDP'},
                        {
                            value: parseFloat(packetInfo.lenTotal - packetInfo.lenKind[0] - packetInfo.lenKind[1]).toFixed(2),
                            name: '其他'
                        }
                    ]
                }]
            });


        });


        setTimeout(refresh, 1000);
    }
}


init();