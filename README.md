### Have it try!
_______________________----
#### 原理是使用网卡的混杂模式，然后使用scoket_raw
#### 过多的printf()会影响速度，应该采取多线程然后直接保存进文件里
> 将包直接写入文件还未实现
> 可以分析的报文有TCP，UDP，ICMP，ARP，IP，DNS
#### 大概就这么多，后面完善后在添加
