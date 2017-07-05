AM_CPPFLAGS = -I$(DPDK_INCLUDE) -I$(top_srcdir)/$(PEAFOWL_INCLUDE)

LDADD =-lpcap -L $(DPDK_LIB) -lrt -lm -ldl $(top_srcdir)/$(PEAFOWL_LIB)

bin_PROGRAMS = extFilter

extFilter_LDFLAGS = -Wl,--whole-archive -lrte_acl -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lrte_ethdev -lrte_eal -lrte_mbuf -lrte_mempool -lrte_mempool_ring -lrte_mempool_stack -lrte_ring -lrte_kvargs -lrte_hash -lrte_cmdline -lrte_net -Wl,--no-whole-archive 

extFilter_SOURCES = main.cpp worker.cpp AhoCorasickPlus.cpp ahocorasick.cpp node.cpp mpool.cpp replace.cpp sender.cpp sendertask.cpp statistictask.cpp reloadtask.cpp flow.cpp acl.cpp cmdlinetask.cpp notification.cpp dpi.cpp

