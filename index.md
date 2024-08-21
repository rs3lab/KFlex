---
title: Home
---

# KFlex

The ability to safely extend OS kernel functionality is a long-standing goal in OS design, with the widespread use of the eBPF framework in Linux and Windows demonstrating the benefits of such extensibility. However, existing solutions for kernel extensibility (including eBPF) are limited and constrain users either in the extent of functionality that they can offload to the kernel or the performance overheads incurred by their extensions.

We present KFlex: a new approach to kernel extensibility that strikes an improved balance between the expressivity and performance of kernel extensions. To do so, KFlex separates the safety of kernel-owned resources (e.g., kernel memory) from the safety of extension-specific resources (e.g., extension memory). This separation enables KFlex to use distinct, bespoke mechanisms to enforce each safety property—automated verification and lightweight runtime checks, respectively—which enables the offload of diverse functionality while incurring low runtime overheads.

We realize KFlex in the context of Linux. We demonstrate that KFlex enables users to offload functionality that cannot be offloaded today and provides significant end-to-end performance benefits for applications. Several of KFlex’s proposed mechanisms have been upstreamed into the Linux kernel mainline, with efforts ongoing for full integration.

The source code is publicly available at the [GitHub repository](https://github.com/rs3lab/KFlex).

The paper is publicly available at [this link](https://rs3lab.github.io/assets/papers/2024/dwivedi:kflex.pdf).

KFlex and its associated paper will be presented at the Proceedings of the 30th ACM Symposium on Operating Systems Principles 2024 (SOSP '24).
