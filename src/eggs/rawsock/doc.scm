(use eggdoc)

(define license
"Copyright (c) 2007, Lenny Frank and Benjamin L. Kurtz.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the Software),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED ASIS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.")

(define email1 "mailto:bk2@alum.wpi.edu")
(define email2 "mailto:elf@ephemeral.net")

(define doc
  `((eggdoc:begin
     (name "rawsock")
     (description (p "UNIX raw socket access"))
     
     (author (url ,email2 "Elf"))
     (author (url ,email1 "Ben Kurtz"))

     (requires
      (url "srfi-66.html" "srfi-66"))
     
     (history
      (version "1.0" "Initial release by Ben Kurtz")
      (version "2.0" "Refactored and cleaned by Elf")
      (version "2.1" "Added non-blocking read by Elf"))

     (usage)
     (download "rawsock.egg")

     (documentation
      (p "This egg provides the ability to open packet sockets, close packet sockets, and perform non-blocking read and write operations.")
      (p "Packet sockets are even less cooked than \"raw\" sockets, letting you set layer 2 fields manually.")
      (p "Currently, this egg has only been ported to OSX and Linux.")
      (p "Future Work: port to Win32 and other targets.")
      
      (group
       (procedure "(raw-socket? OBJ)" (p "Returns #t if OBJ is a raw socket."))
       (procedure "(open-raw-socket INTERFACE)" (p "Opens a packet socket on the given interface name."))
       (procedure "(raw-socket-open? RAWSOCK)" (p "Returns #t if RAWSOCK is an open raw socket."))
       (procedure "(raw-send RAWSOCK BUFFER)" 
                  (p "Sends a buffer of bytes out the opened socket.  " 
                     (tt "RAWSOCK") " is the socket returned by open-raw-socket.  "
                     (tt "BUFFER") " is the u8vector containing the data to be sent.")) 
       (procedure "(raw-recv RAWSOCK)"
                  (p "Receives data on RAWSOCK.  Returns a pair of (number-of-bytes . u8vector-with-data)."))
       (procedure "(close-raw-socket RAWSOCK)" (p "Closes the given packet socket."))
       ))
     (section "License" (pre ,license)))))

(eggdoc->html doc)
