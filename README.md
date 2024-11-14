该项目的详细信息见博客：

 [PE64shell](https://mp.weixin.qq.com/s?__biz=MzkyNTUyNDMyOA==&mid=2247487455&idx=1&sn=bffa49b575ba8d8ca154a9dbb2ac2a74&chksm=c1c407d8f6b38ece0d3228815c14ae5c212a5e42f9833ce577232bb860783b78c3ae7e216545#rd)



## 前记

- 开源的关于PE压缩和加密壳几乎都是32位，于是学习写一个64位的壳供参考，其原理差别不大

- 学写PE壳是熟悉PE结构很好的方式




## x64壳

代码分布：

stub：外壳，负责解密.text，解析修复IAT，跳转到原来的OEP

PE64shell：将stub的.text节和导入表打包尾加到待加壳的PE并修改一系列文件头信息

效果展示：

![show](pic/show.gif)





## reference

```
https://blog.schnee.moe/posts/SimpleDpack/
https://www.cnblogs.com/z5onk0/p/17287215.html
```

