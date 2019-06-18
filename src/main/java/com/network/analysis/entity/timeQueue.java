package com.network.analysis.entity;

import java.util.LinkedList;
import java.util.Queue;

/**
 * Created by Garlan on 2019/6/18.
 */
public class timeQueue {
    private int[] queue;
    private int maxLen = 0;   //数组长度,使用时maxLen-1应为历史长度
    private long startTime = 0;
    private int space = 0;   //间隙

    public timeQueue(int maxLen, int space) {
        this.maxLen = maxLen;
        this.space = space;
        this.queue = new int[maxLen];
        for (int i = 0; i < maxLen; i++) {
            this.queue[i] = 0;
        }
    }

    public void add(long time) {
        if (this.startTime == 0) {
            this.startTime = time;
        }
        if (time - startTime < maxLen * space) {
            int d = (int) ((time - startTime) / space);
            queue[d]++;
        } else if (time - startTime < maxLen * space * 2) {
            int d = (int) ((time - startTime) / space) - maxLen + 1;
            for (int i = 0; i < maxLen; i++) {
                if ((i + d) < maxLen) {
                    queue[i] = queue[i + d];
                } else {
                    queue[i] = 0;
                }
            }
            queue[maxLen - 1]++;
            startTime += space * d;
        } else {
            this.startTime = time;
            for (int i = 0; i < maxLen; i++) {
                this.queue[i] = 0;
            }
            queue[maxLen - 1] = 1;
        }
    }


    public int average(){
        int sum=0;
        for (int i=0;i<this.maxLen-1;i++){
            sum+=queue[i];
        }
        return sum/maxLen;
    }

    public int last(){
        return queue[maxLen-1];
    }

}
