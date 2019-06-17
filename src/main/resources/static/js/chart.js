//每秒数据包折线图初始化
function chartOption1(data) {
    var option = {
        title: {
            text: '每秒数据包数量'
        },
        xAxis: {
            type: 'time',
            splitLine: {
                show: false
            },
            smooth: true,
            formatter: function (value) {
                var t_date = new Date(value);
                return [t_date.getFullYear(), t_date.getMonth() + 1, t_date.getDate()].join('/') + " "
                    + [t_date.getHours(), t_date.getMinutes()].join(':');
            }
        },
        yAxis: {
            type: 'value',
            boundaryGap: [0, '100%'],
            splitLine: {
                show: false
            },
            smooth: true
        },
        series: [{
            name: '数据量',
            type: 'line',
            color: ['#87CEFA'],
            showSymbol: false,
            hoverAnimation: false,
            data: data
        }]
    };
    return option;
}

//数据包每秒大小图初始化
function chartOption2(data) {
    var option = {
        title: {
            text: '每秒数据包大小'
        },
        xAxis: {
            type: 'time',
            splitLine: {
                show: false
            },
            smooth: true,
            formatter: function (value) {
                var t_date = new Date(value);
                return [t_date.getFullYear(), t_date.getMonth() + 1, t_date.getDate()].join('/') + " "
                    + [t_date.getHours(), t_date.getMinutes()].join(':');
            }
        },
        yAxis: {
            type: 'value',
            boundaryGap: [0, '100%'],
            splitLine: {
                show: false
            },
            smooth: true
        },
        series: [{
            name: '数据量',
            type: 'line',
            color: ['#87CEFA'],
            showSymbol: false,
            hoverAnimation: false,
            data: data
        }]
    };
    return option;
}



//数据包总数量图初始化
function chartOption3(data) {
    var option = {
        title: {
            text: '数据包总数'
        },
        xAxis: {
            type: 'time',
            splitLine: {
                show: false
            },
            smooth: true,
            formatter: function (value) {
                var t_date = new Date(value);
                return [t_date.getFullYear(), t_date.getMonth() + 1, t_date.getDate()].join('/') + " "
                    + [t_date.getHours(), t_date.getMinutes()].join(':');
            }
        },
        yAxis: {
            type: 'value',
            boundaryGap: [0, '100%'],
            splitLine: {
                show: false
            },
            smooth: true
        },
        dataZoom: [{
            type: 'slider',//图表下方的伸缩条
            show: true, //是否显示
            realtime: true, //拖动时，是否实时更新系列的视图
            start: 0, //伸缩条开始位置（1-100），可以随时更改
            end: 100  //伸缩条结束位置（1-100），可以随时更改
        }],
        series: [{
            name: '数据量',
            type: 'line',
            color: ['#87CEFA'],
            showSymbol: false,
            hoverAnimation: false,
            areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{
                    offset: 0,
                    color: 'rgb(16,255,102)'
                }, {
                    offset: 1,
                    color: 'rgb(62,160,255)'
                }])
            },
            data: data
        }]
    };
    return option;
}

//数据包总大小图初始化
function chartOption4(data) {
    var option = {
        title: {
            text: '数据包总量'
        },
        xAxis: {
            type: 'time',
            splitLine: {
                show: false
            },
            smooth: true,
            formatter: function (value) {
                var t_date = new Date(value);
                return [t_date.getFullYear(), t_date.getMonth() + 1, t_date.getDate()].join('/') + " "
                    + [t_date.getHours(), t_date.getMinutes()].join(':');
            }
        },
        yAxis: {
            type: 'value',
            boundaryGap: [0, '100%'],
            splitLine: {
                show: false
            },
            smooth: true
        },
        dataZoom: [{
            type: 'slider',//图表下方的伸缩条
            show: true, //是否显示
            realtime: true, //拖动时，是否实时更新系列的视图
            start: 0, //伸缩条开始位置（1-100），可以随时更改
            end: 100  //伸缩条结束位置（1-100），可以随时更改
        }],
        series: [{
            name: '数据量',
            type: 'line',
            color: ['#87CEFA'],
            showSymbol: false,
            hoverAnimation: true,
            areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{
                    offset: 0,
                    color: 'rgb(16,255,102)'
                }, {
                    offset: 1,
                    color: 'rgb(62,160,255)'
                }])
            },
            data: data
        }]
    };
    return option;
}



//TCP+UDP+OTHER 数据包数量比例饼图初始化
function chartOption5() {
    var option = {
        title: {
            text: '数据包数量比例',
            x: 'center'
        },
        tooltip: {
            trigger: 'item',
            formatter: "{a} <br/>{b} : {c} ({d}%)"
        },
        legend: {
            orient: 'vertical',
            left: 'left',
            data: ['TCP', 'UDP', '其他']
        },
        color: ['#08d683', '#ffc41e', '#708b4b'],
        series: [
            {
                name: '协议',
                type: 'pie',
                radius: '55%',
                center: ['50%', '60%'],
                data: [
                    {value: 0, name: 'TCP'},
                    {value: 0, name: 'UDP'},
                    {value: 0, name: '其他'}
                ],
                itemStyle: {
                    emphasis: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                }
            }
        ]
    };

    return option;
}

//TCP+UDP+OTHER 数据包大小比例饼图初始化
function chartOption6() {
    var option = {
        title: {
            text: '数据包大小比例',
            x: 'center'
        },
        tooltip: {
            trigger: 'item',
            formatter: "{a} <br/>{b} : {c}KB ({d}%)"
        },
        legend: {
            orient: 'vertical',
            left: 'left',
            data: ['TCP', 'UDP', '其他']
        },
        color: ['#08d683', '#ffc41e', '#708b4b'],
        series: [
            {
                name: '协议',
                type: 'pie',
                radius: '55%',
                center: ['50%', '60%'],
                data: [
                    {value: 0, name: 'TCP'},
                    {value: 0, name: 'UDP'},
                    {value: 0, name: '其他'}
                ],
                itemStyle: {
                    emphasis: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                }
            }
        ]
    };

    return option;
}