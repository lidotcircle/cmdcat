## TCP stream connection state (netstat)

### TIME_WAIT
local endpoint has closed the connection waiting for remote endpoint send FIN packet

### CLOSE_WAIT
remote endpoint has send **FIN** packet waiting for local endpoint close the connection

### FIN_WAIT2
local endpoint has send **FIN** packet, but still possiblely recieve packet from remote endpoint.

### ESTABLISHED
local endpoint can send and recieve the socket.

### LISTENING
local endpoint can accept the socket to get a connection.

``` c
/*
               ESTABLISHED -----------------------------------------------------------------> TIME_WAIT
                    |          |          close(socket)               <release>                   |
                    |          |          shutdown(socket, SHUT_RDWR) <own>                       |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                                                  |
        recieve FIN |          | send FIN                                                         | recieve FIN
                    |          | shutdown(socket, SHUT_WR)                                        |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                                                  |
                    |          |                                   recieve FIN                    |
                    |          |-------------------> FIN_WAIT2 --------------------               |
                    |                                                             |               |
                    |                                                             |               |
                    |                   shutdown(socket, SHUT_WR)                 |               |
                    |                   shutdown(socket, SHUT_RDWR)               |               |
                    v                   close(socket)                             |               v
                CLOSE_WAIT --------------------------------------------------------------------> FINISH
*/
```


## shutdown() and close()

### shutdown(socket, SHUT_WR)
send a **FIN** packet.  

### shutdown(socket, SHUT_RD)
doesn't send addtional packet, but `recv(socket) == 0`

### shutdown(socket, SHUT_RDWR)
`SHUT_WR` + `SHUT_RD`

### close(socket)
send a **FIN** packet, change state of this socket according to previous state like `SHUT_WR`.
Detach this socket from this process (`lsof` shows file descriptor of this process doesn't contain the socket).
Any addtional operation on the socket descriptor will cause a `EBADF` (Bad file descripor) error.

