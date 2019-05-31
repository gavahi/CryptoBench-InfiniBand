!     -*- Mode: Fortran; -*-
!
!     (C) 2001 by Argonne National Laboratory.
!     See COPYRIGHT in top-level directory.
!
       subroutine mpirinitf( )
       integer mpi_status_size
       parameter (mpi_status_size=5)
!      STATUS_IGNORE, STATUSES_IGNORE
       integer si(mpi_status_size), ssi(mpi_status_size,1)
!      BOTTOM, IN_PLACE, UNWEIGHTED, ERRCODES_IGNORE
       integer bt, ip, uw, ecsi(1)
!      ARGVS_NULL, ARGV_NULL
       character*1 asn(1,1), an(1)
       common /MPIFCMB5/ uw
       common /MPIFCMB9/ we
       common /MPIPRIV1/ bt, ip, si
       common /MPIPRIV2/ ssi, ecsi
       common /MPIPRIVC/ asn, an
       save /MPIFCMB5/
       save /MPIFCMB9/
       save /MPIPRIV1/, /MPIPRIV2/
       save /MPIPRIVC/
!      MPI_ARGVS_NULL 
!      (Fortran requires character data in a separate common block)
       call mpirinitc(si, ssi, bt, ip, uw, ecsi, asn, we)
       call mpirinitc2(an)
       return
       end
