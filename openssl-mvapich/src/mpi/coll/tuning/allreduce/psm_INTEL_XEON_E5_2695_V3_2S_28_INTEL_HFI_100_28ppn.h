/*
 * Copyright (c) 2001-2018, The Ohio State University. All rights
 * reserved.
 *
 * This file is part of the MVAPICH2 software package developed by the
 * team members of The Ohio State University's Network-Based Computing
 * Laboratory (NBCL), headed by Professor Dhabaleswar K. (DK) Panda.
 *
 * For detailed copyright and licensing information, please refer to the
 * copyright file COPYRIGHT in the top level MVAPICH2 directory.
 */

#define PSM__INTEL_XEON_E5_2695_V3_2S_28_INTEL_HFI_100__28PPN {		\
	{               \
	28,             \
	0,              \
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0},              \
	19,             \
	{               \
	{4, &MPIR_Allreduce_pt2pt_rd_MV2},              \
	{8, &MPIR_Allreduce_pt2pt_rd_MV2},              \
	{16, &MPIR_Allreduce_pt2pt_rd_MV2},             \
	{32, &MPIR_Allreduce_pt2pt_rs_MV2},             \
	{64, &MPIR_Allreduce_pt2pt_rs_MV2},             \
	{128, &MPIR_Allreduce_pt2pt_rs_MV2},            \
	{256, &MPIR_Allreduce_pt2pt_rs_MV2},            \
	{512, &MPIR_Allreduce_pt2pt_rd_MV2},            \
	{1024, &MPIR_Allreduce_pt2pt_rd_MV2},           \
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},           \
	{4096, &MPIR_Allreduce_pt2pt_rs_MV2},           \
	{8192, &MPIR_Allreduce_pt2pt_rs_MV2},           \
	{16384, &MPIR_Allreduce_pt2pt_rs_MV2},          \
	{32768, &MPIR_Allreduce_pt2pt_rs_MV2},          \
	{65536, &MPIR_Allreduce_pt2pt_rs_MV2},          \
	{131072, &MPIR_Allreduce_pt2pt_rs_MV2},         \
	{262144, &MPIR_Allreduce_pt2pt_rs_MV2},         \
	{524288, &MPIR_Allreduce_pt2pt_rs_MV2},         \
	{1048576, &MPIR_Allreduce_pt2pt_rs_MV2}         \
	},              \
	19,             \
	{               \
	{4, &MPIR_Allreduce_reduce_shmem_MV2},          \
	{8, &MPIR_Allreduce_reduce_shmem_MV2},          \
	{16, &MPIR_Allreduce_reduce_shmem_MV2},         \
	{32, &MPIR_Allreduce_reduce_shmem_MV2},         \
	{64, &MPIR_Allreduce_reduce_shmem_MV2},         \
	{128, &MPIR_Allreduce_reduce_shmem_MV2},                \
	{256, &MPIR_Allreduce_reduce_shmem_MV2},                \
	{512, &MPIR_Allreduce_reduce_shmem_MV2},                \
	{1024, &MPIR_Allreduce_pt2pt_rs_MV2},           \
	{2048, &MPIR_Allreduce_pt2pt_rs_MV2},           \
	{4096, &MPIR_Allreduce_reduce_p2p_MV2},         \
	{8192, &MPIR_Allreduce_reduce_p2p_MV2},         \
	{16384, &MPIR_Allreduce_reduce_p2p_MV2},                \
	{32768, &MPIR_Allreduce_pt2pt_rs_MV2},          \
	{65536, &MPIR_Allreduce_reduce_p2p_MV2},                \
	{131072, &MPIR_Allreduce_reduce_p2p_MV2},               \
	{262144, &MPIR_Allreduce_reduce_p2p_MV2},               \
	{524288, &MPIR_Allreduce_pt2pt_rd_MV2},         \
	{1048576, &MPIR_Allreduce_reduce_p2p_MV2}               \
	}               \
	},                \
	{		\
	56,		\
	0,		\
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{8, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{16, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{32, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{64, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{128, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{256, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{512, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{1024, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{4096, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8192, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{16384, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{32768, &MPIR_Allreduce_mcst_reduce_two_level_helper_MV2},		\
	{65536, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{131072, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{262144, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{524288, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{1048576, &MPIR_Allreduce_pt2pt_rs_MV2}		\
	},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{8, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{16, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{32, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{64, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{128, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{256, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{512, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{1024, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{4096, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{8192, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{16384, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{32768, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{65536, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{131072, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{262144, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{524288, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{1048576, &MPIR_Allreduce_reduce_p2p_MV2}		\
	}		\
	},		 \
	{		\
	112,		\
	0,		\
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{16, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{32, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{64, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{128, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{256, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{512, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{1024, &MPIR_Allreduce_mcst_reduce_redscat_gather_MV2},		\
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{4096, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8192, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{16384, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{32768, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{65536, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{131072, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{262144, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{524288, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{1048576, &MPIR_Allreduce_pt2pt_rs_MV2}		\
	},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{8, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{16, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{32, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{64, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{128, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{256, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{512, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{1024, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{2048, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{4096, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8192, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{16384, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{32768, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{65536, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{131072, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{262144, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{524288, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{1048576, &MPIR_Allreduce_reduce_p2p_MV2}		\
	}		\
	},		 \
	{		\
	224,		\
	0,		\
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{16, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{32, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{64, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{128, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{256, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{512, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{1024, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{2048, &MPIR_Allreduce_mcst_reduce_two_level_helper_MV2},		\
	{4096, &MPIR_Allreduce_mcst_reduce_two_level_helper_MV2},		\
	{8192, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{16384, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{32768, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{65536, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{131072, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{262144, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{524288, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{1048576, &MPIR_Allreduce_pt2pt_rs_MV2}		\
	},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{8, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{16, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{32, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{64, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{128, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{256, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{512, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{1024, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{2048, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{4096, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{8192, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{16384, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{32768, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{65536, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{131072, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{262144, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{524288, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{1048576, &MPIR_Allreduce_reduce_p2p_MV2}		\
	}		\
	},		 \
	{		\
	448,		\
	0,		\
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{8, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{16, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{32, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{64, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{128, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{256, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{512, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{1024, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{4096, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{8192, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{16384, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{32768, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{65536, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{131072, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{262144, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{524288, &MPIR_Allreduce_pt2pt_rs_MV2},		\
	{1048576, &MPIR_Allreduce_pt2pt_rs_MV2}		\
	},		\
	19,		\
	{		\
	{4, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{8, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{16, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{32, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{64, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{128, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{256, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{512, &MPIR_Allreduce_reduce_shmem_MV2},		\
	{1024, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{2048, &MPIR_Allreduce_pt2pt_rd_MV2},		\
	{4096, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{8192, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{16384, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{32768, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{65536, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{131072, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{262144, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{524288, &MPIR_Allreduce_reduce_p2p_MV2},		\
	{1048576, &MPIR_Allreduce_reduce_p2p_MV2}		\
	}		\
	}		 \
}
