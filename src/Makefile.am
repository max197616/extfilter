AM_CPPFLAGS = -I$(DPDK_INCLUDE) -I$(top_srcdir)/$(PEAFOWL_INCLUDE) -I$(top_srcdir)/$(MARISA_INCLUDE)

LDADD =-lpcap -L $(DPDK_LIB) -lrt -lm -ldl $(top_srcdir)/$(PEAFOWL_LIB) $(top_srcdir)/$(MARISA_LIB)

bin_PROGRAMS = extFilter

extFilter_LDFLAGS = -Wl,--whole-archive -lrte_acl -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lrte_ethdev -lrte_eal -lrte_mbuf -lrte_mempool -lrte_mempool_ring -lrte_mempool_stack -lrte_ring -lrte_kvargs -lrte_hash -lrte_cmdline -lrte_net -Wl,--no-whole-archive 

extFilter_SOURCES = main.cpp worker.cpp sender.cpp statistictask.cpp reloadtask.cpp flow.cpp acl.cpp cmdlinetask.cpp notification.cpp tries.cpp utils.cpp http.cpp ssl.cpp ssli.cpp bworker.cpp

