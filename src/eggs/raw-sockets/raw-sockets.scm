;;;; raw-sockets.scm
;
; Copyright (c) 2007, Benjamin L. Kurtz
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
; conditions are met:
;
;   Redistributions of source code must retain the above copyright notice, this list of conditions and the following
;     disclaimer. 
;   Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
;     disclaimer in the documentation and/or other materials provided with the distribution. 
;   Neither the name of the author nor the names of its contributors may be used to endorse or promote
;     products derived from this software without specific prior written permission. 
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
; AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
; OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.
;
; Send bugs, suggestions and ideas to: 
;
; bk2@alum.wpi.edu
;
; Benjamin L. Kurtz


(declare
  (export
      raw-open
      raw-send
      raw-close
	  ))


#>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
         
#ifdef __MACH__       
#include <net/ndrv.h>
#else
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>         
#endif
         
int fd;
struct sockaddr saddr; 
<#

#>!
static int 
raw_open(char *iface)
{

#ifdef __MACH__ 
	fd = socket(AF_NDRV, SOCK_RAW, 0);
#else
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#endif

    if(fd < 0) {
		return -1;
	}
	
	// create the socket address
#ifdef __MACH__                 
    saddr.sa_len = sizeof(struct sockaddr);       
	saddr.sa_family = AF_NDRV;
#else
    saddr.sa_family = AF_PACKET;
#endif                      
                      
    strcpy(saddr.sa_data, iface);
	//if( bind(fd, &saddr, sizeof(saddr)) == -1 )
    bind(fd, &saddr, sizeof(saddr));
    return 0;
    // must make call to bind or it kernel panics.
    // call to bind always fails. wtf?                                       
    //else
    //	return -1;
}

static int 
raw_send(unsigned char *pkt, size_t len)
{
	int nleft 	 = len;
	int nwritten = 0;
	unsigned char * ptr = pkt;

	while( nleft > 0 )
	{
		nwritten = sendto( fd, ptr, nleft, 0, &saddr, sizeof(saddr) );
		if( nwritten <= 0 )
		{
			if( errno == EINTR )
			{
				nwritten = 0; // one more try
			}
			else
			{
                return -1;
            }
		}
		nleft -= nwritten;
		ptr += nwritten;
	}

	return 0;
}

static int 
raw_close()
{
	return close(fd);
}
<#

(define strerror (foreign-lambda c-string "strerror" int))
(define-foreign-variable errno int)
 
(define (raw-error loc msg . args)
  (signal
   (make-composite-condition
    (make-property-condition 'exn 'message (string-append msg " - " (strerror errno)) 'location loc args args)
    (make-property-condition 'raw 'errno errno) ) ) )

(define (raw-open interface)
  (let ([n (raw_open interface)])
    (if (negative? n)
        (raw-error 'raw-open "can not open interface" interface)
        #t)))

(define (raw-send pkt len)
  (let ([n (raw_send pkt len)])
    (if (negative? n)
        (raw-error 'raw-send "send failed")
        #t)))

(define (raw-close)
  (let ([n (raw_close)])
    (if (negative? n)
        (raw-error 'raw-close "close failed")
        #t)))