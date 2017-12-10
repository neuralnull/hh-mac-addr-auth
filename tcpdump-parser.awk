function hextostr(start, end) {
    str = ""
    for (i = start; i <= end; i++) {
        ch1 = "0x" substr($i, 1, 2)
        ch2 = "0x" substr($i, 3, 2)
        str = str sprintf("%c%c", strtonum(ch1), strtonum(ch2))
    }
    return str
}

{
    if (substr($0, 1, 1) != "\t") {
        mac = $1
        token = ""
        read_token = 0
    } else if ($1 == "0x0050:") {
        read_token = 1
    }

    if (read_token) {
        token = token hextostr(2, NF)
        end = index(token, "HTTP")

        if (end > 0) {
            read_token = 0
            token = substr(token, 1, end - 2)
            end = index(token, "&")

            if (end > 0) {
                token = substr(token, 1, end - 2)
            }
            
            if (length(token) > 0) {
                print token, mac
                fflush()
            }
        }
    }
}