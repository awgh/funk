(use eggdoc)

(define license
"Copyright (c) 2007, Benjamin L. Kurtz.  All rights reserved.

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

(define email "mailto:bk2@alum.wpi.edu")

(define doc
  `((eggdoc:begin
     (name "raw-sockets")
     (description (p "Simple access to UNIX raw sockets"))
     
     (author (url ,email "Ben Kurtz"))

     (requires
      (url "srfi-66.html" "srfi-66"))
     
     (history
      (version "1.0" "Initial release"))

     (usage)
     (download "raw-sockets.egg")

     (documentation
      (p "This egg provides the ability to open, send, and close packet sockets.")
      (p "Packet sockets are even less cooked than "raw" sockets, letting you set layer 2 fields manually.")
      (p "Currently, this egg has only been ported to OSX and Linux.")
      (p "Future Work: port to Win32, make work with more than one interface at a time.")
      
      (group
       (procedure "(raw-open INTERFACE)" (p "Opens a packet socket on the given interface name."))
       (procedure "(raw-send BUFFER LEN)" 
                  (p "Sends a buffer of bytes out the opened socket. " 
                     (tt "BUFFER") " is the u8vector containing the data to be sent, " 
                     (tt "LEN") " is the length of " 
                     (tt "BUFFER") " in octets."))
       (procedure "(raw-close)" (p "Closes the packet socket."))
       ))
     (section "License" (pre ,license)))))

(eggdoc->html doc)
