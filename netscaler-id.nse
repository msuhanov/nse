local nmap = require('nmap')
local stdnse = require('stdnse')
local shortport = require('shortport')
local packet = require('packet')

description = [[
Try to fingerprint the NetScaler's TCP/IP stack on virtual IP addresses (VIPs) and other interfaces going via the Packet Processing Engine (NSPPE).

Works against default NetScaler installations, as well as appliances with the "enhanced ISN generation" flag enabled.

Nmap must be run in privileged mode. Only IPv4 is supported.

Source ports must be intact during each connection to a server (no source port translation).
]]

author = "Maxim Suhanov"
license = "Same as Nmap, see https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

-- Written by: Maxim Suhanov (CICADA8)
-- Version: 0.1
-- Date: 2026-04-20

portrule = shortport.port_or_service({22, 80, 443}, {"ssh", "http", "https"}, "tcp", "open")

action = function(host, port)
  if not nmap.is_privileged() then
    return
  end

  local dst_ip_size = { string.byte(host.bin_ip, 1, #host.bin_ip) }
  if #dst_ip_size ~= 4 then
    -- Not IPv4
    return
  end

  -- The first test, preliminary, is this:
  --  - Send TCP SYN packets from 3 different source ports
  --  - Receive 3 TCP SYN+ACK packets (to each source port), ISNs coming from the server were independently generated for each TCP SYN packet we sent
  --  - Before the server's secret is rotated (happens every 120 seconds), the server's ISNs will remain constant for every (src_ip, dst_ip, src_port, dst_port) tuple
  --  - After the server's secret have been rotated, the new (changed) server's ISNs will remain constant for every (src_ip, dst_ip, src_port, dst_port) tuple
  -- This test tries to catch the server's ISNs before and after the rotation, assuming they will differ (the opposite situation is negligible)
  -- Some TCP/IP stacks have similar behavior, so we need to measure the secret's rotation interval later, which is hardcoded to 120 seconds

  -- Network timeout (how long to wait until replies arrive)
  local network_timeout_ms = 6000
  
  -- TCP SYN placeholder
  local tcp_hdr = stdnse.fromhex("000000004141414100000000a002faf000000000020405b40402080a28541468000000000103030a")

  local do_preliminary_test = function(host, port)
    -- 1st probe (TCP SYN)
    local pkt1 = packet.Packet:new()
    pkt1:build_ip_packet(host.bin_ip_src, host.bin_ip, tcp_hdr, nil, 0x0AB0, nil, nil, 64, 6)
    pkt1:ip_parse()
    pkt1:tcp_parse()
    pkt1:tcp_set_sport(64441)
    pkt1:tcp_set_dport(port.number)
    pkt1:tcp_count_checksum()

    -- 2nd probe (TCP SYN)
    local pkt2 = packet.Packet:new()
    pkt2:build_ip_packet(host.bin_ip_src, host.bin_ip, tcp_hdr, nil, 0x1BC1, nil, nil, 64, 6)
    pkt2:ip_parse()
    pkt2:tcp_parse()
    pkt2:tcp_set_sport(64442)
    pkt2:tcp_set_dport(port.number)
    pkt2:tcp_count_checksum()

    -- 3rd probe (TCP SYN)
    local pkt3 = packet.Packet:new()
    pkt3:build_ip_packet(host.bin_ip_src, host.bin_ip, tcp_hdr, nil, 0x2CD2, nil, nil, 64, 6)
    pkt3:ip_parse()
    pkt3:tcp_parse()
    pkt3:tcp_set_sport(64443)
    pkt3:tcp_set_dport(port.number)
    pkt3:tcp_count_checksum()

    -- Create a pcap capture socket
    local socket = nmap.new_socket()
    local pcap_filter = "tcp and src host " .. host.ip .. " and src port " .. port.number .. " and dst port (64441 or 64442 or 64443)" ..
                  " and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
    socket:pcap_open(host.interface, 128, false, pcap_filter)

    -- Don't wait for too long
    socket:set_timeout(network_timeout_ms)

    -- Send all probes at once, wait for replies
    stdnse.verbose(2, "Sending 3 probes")
    local dnet = nmap.new_dnet()
    dnet:ip_open()
    dnet:ip_send(pkt1.buf)
    dnet:ip_send(pkt2.buf)
    dnet:ip_send(pkt3.buf)
    dnet:ip_close()

    local pcap_run = true
    local pktr1_isn = nil
    local pktr2_isn = nil
    local pktr3_isn = nil
    local has_timestamps = false
    local has_high_ttl = false
    while pcap_run do
      local status, plen, l2data, l3data = socket:pcap_receive()
      pcap_run = status

      if status then
        local pktr = packet.Packet:new(l3data)
        if pktr1_isn == nil and pktr.tcp_dport == 64441 and pktr.tcp_ack == 0x41414142 then
          stdnse.verbose(2, "Received reply to probe #1")
          pktr1_isn = pktr.tcp_seq
        elseif pktr2_isn == nil and pktr.tcp_dport == 64442 and pktr.tcp_ack == 0x41414142 then
          stdnse.verbose(2, "Received reply to probe #2")
          pktr2_isn = pktr.tcp_seq
        elseif pktr3_isn == nil and pktr.tcp_dport == 64443 and pktr.tcp_ack == 0x41414142 then
          stdnse.verbose(2, "Received reply to probe #3")
          pktr3_isn = pktr.tcp_seq
        end

        if pktr.tcp_opt_t1 ~= nil and not has_timestamps then
          has_timestamps = true
          stdnse.verbose(2, "Got TCP timestamps in reply")
        end

        if pktr.ip_ttl >= 200 then
          has_high_ttl = true
          stdnse.verbose(2, "Got high (>= 200) IP TTL")
        end
      end

      if pktr1_isn ~= nil and pktr2_isn ~= nil and pktr3_isn ~= nil then
        -- Got 3 replies, stop capturing
        break
      end
    end

    socket:pcap_close()

    return pktr1_isn, pktr2_isn, pktr3_isn, has_timestamps, has_high_ttl
  end

  local test1_isn1 = nil
  local test1_isn2 = nil
  local test1_isn3 = nil
  local test2_isn1 = nil
  local test2_isn2 = nil
  local test2_isn3 = nil
  local test3_isn1 = nil
  local test3_isn2 = nil
  local test3_isn3 = nil
  local sleep_interval = 25
  local has_timestamps = nil
  local has_high_ttl = nil

  test1_isn1, test1_isn2, test1_isn3, has_timestamps, has_high_ttl = do_preliminary_test(host, port)
  if test1_isn1 == nil or test1_isn2 == nil or test1_isn3 == nil then
    stdnse.verbose(2, "Test #1 - not enough replies, retrying")
    test1_isn1, test1_isn2, test1_isn3 = do_preliminary_test(host, port)
    if test1_isn1 == nil or test1_isn2 == nil or test1_isn3 == nil then
      -- Non-ideal network conditions (packet loss)
      stdnse.verbose(2, "Test #1 - still not enough replies, exiting")
      return
    end
  end

  stdnse.verbose(2, "Sleeping for %d secs", sleep_interval)
  stdnse.sleep(sleep_interval)

  test2_isn1, test2_isn2, test2_isn3 = do_preliminary_test(host, port)
  if test2_isn1 == nil or test2_isn2 == nil or test2_isn3 == nil then
    stdnse.verbose(2, "Test #2 - not enough replies, retrying")
    test2_isn1, test2_isn2, test2_isn3 = do_preliminary_test(host, port)
    if test2_isn1 == nil or test2_isn2 == nil or test2_isn3 == nil then
      -- Non-ideal network conditions (packet loss)
      stdnse.verbose(2, "Test #2 - still not enough replies, exiting")
      return
    end
  end

  local should_change
  if test1_isn1 == test2_isn1 and test1_isn2 == test2_isn2 and test1_isn3 == test2_isn3 then
    -- Server-side TCP ISNs haven't changed, wait longer and see if they change (they must in the NetScaler's case)
    -- If the target is NetScaler: two tests landed within a single (current) 120-second secret rotation window,
    --   need to wait for 120 seconds for the window to change

    stdnse.verbose(2, "TCP ISNs are the same in tests #1 & #2")    
    sleep_interval = 120
    should_change = true
  elseif test1_isn1 ~= test2_isn1 and test1_isn2 ~= test2_isn2 and test1_isn3 ~= test2_isn3 then
    -- Server-side TCP ISNs have changed, wait again and see if they change once more (they shouldn't in the NetScaler case)
    -- If the target is NetScaler: two tests landed in adjacent 120-second secret rotation windows,
    --   no need to wait for 120 seconds (the window has changed between tests)

    stdnse.verbose(2, "TCP ISNs are NOT the same in tests #1 & #2")       
    should_change = false
  else
    -- Inconclusive, bail out
    stdnse.verbose(2, "Tests #1 & #2 have inconclusive results, exiting")
    return 
  end

  stdnse.verbose(2, "Sleeping for %d secs", sleep_interval)
  stdnse.sleep(sleep_interval)

  test3_isn1, test3_isn2, test3_isn3 = do_preliminary_test(host, port)
  if test3_isn1 == nil or test3_isn2 == nil or test3_isn3 == nil then
    stdnse.verbose(2, "Test #3 - not enough replies, retrying")
    test3_isn1, test3_isn2, test3_isn3 = do_preliminary_test(host, port)
    if test3_isn1 == nil or test3_isn2 == nil or test3_isn3 == nil then
      -- Non-ideal network conditions (packet loss)
      stdnse.verbose(2, "Test #3 - still not enough replies, exiting")
      return
    end
  end

  local netscaler_suspected = false
  if should_change then
    if test1_isn1 ~= test3_isn1 and test1_isn2 ~= test3_isn2 and test1_isn3 ~= test3_isn3 then
      -- If the target is NetScaler: the third test landed in a new (current) 120-second secret rotation window
      --   (tests #1 & #2 landed the previous window, test #3 landed in the current window)

      stdnse.verbose(2, "TCP ISNs are NOT the same in tests #1 & #3")    
      netscaler_suspected = true
    end
  else
    if test2_isn1 == test3_isn1 and test2_isn2 == test3_isn2 and test2_isn3 == test3_isn3 then
      -- If the target is NetScaler: the third test landed in the same 120-second secret rotation window as the second test

      stdnse.verbose(2, "TCP ISNs are the same in tests #2 & #3")    
      netscaler_suspected = true
    end
  end

  if not netscaler_suspected then
    -- No need to try further, bail out
    stdnse.verbose(2, "Exiting after preliminary test")
    return
  end
  stdnse.verbose(2, "Starting second test")

  -- Second test: try to measure the server's secret rotation interval, should be 120 seconds (hardcoded)

  local do_main_test = function(host, port)
    -- Single probe
    local pkt = packet.Packet:new()
    pkt:build_ip_packet(host.bin_ip_src, host.bin_ip, tcp_hdr, nil, 0x10A0, nil, nil, 64, 6)
    pkt:ip_parse()
    pkt:tcp_parse()
    pkt:tcp_set_sport(64431)
    pkt:tcp_set_dport(port.number)
    pkt:tcp_count_checksum()

    -- Create a pcap capture socket
    local socket = nmap.new_socket()
    local pcap_filter = "tcp and src host " .. host.ip .. " and src port " .. port.number .. " and dst port 64431" ..
                  " and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
    socket:pcap_open(host.interface, 128, false, pcap_filter)

    -- Don't wait for too long
    socket:set_timeout(network_timeout_ms)

    -- Send our probes
    local dnet = nmap.new_dnet()
    dnet:ip_open()

    local pktr_isn = nil
    local time_first_change = nil
    local time_second_change = nil
    local i = 0

    while i < 25 do
      i = i + 1

      -- Send the same probe twice
      stdnse.verbose(2, "Sending 2 probes")
      dnet:ip_send(pkt.buf)
      dnet:ip_send(pkt.buf)

      local pcap_run = true
      while pcap_run do
        local status, plen, l2data, l3data = socket:pcap_receive()
        pcap_run = status

        if status then
          local pktr = packet.Packet:new(l3data)

          if pktr.tcp_ack == 0x41414142 then
            stdnse.verbose(2, "Received reply to probe")
            if pktr_isn == nil then
              pktr_isn = pktr.tcp_seq
            elseif pktr.tcp_seq ~= pktr_isn then
              pktr_isn = pktr.tcp_seq
              if time_first_change == nil then
                time_first_change = nmap.clock()
                stdnse.verbose(2, "First ISN change in replies")
              elseif time_second_change == nil then
                time_second_change = nmap.clock()
                stdnse.verbose(2, "Second ISN change in replies")
                goto exit
              end
            end
          end
        end

        if time_first_change ~= nil and time_second_change ~= nil then
          -- Got everything we need, stop
          goto exit
        end
      end

      stdnse.verbose(2, "Sleeping for 8 secs")
      stdnse.sleep(8)
    end


    ::exit::
    socket:pcap_close()
    dnet:ip_close()

    return time_first_change, time_second_change
  end

  local time_1 = nil
  local time_2 = nil
  local confidence_level = "medium" -- Default confidence level to account similar (and unusual) TCP stacks

  time_1, time_2 = do_main_test(host, port)
  if time_1 == nil or time_2 == nil then
    return
  elseif time_2 > time_1 then
    stdnse.verbose(2, "ISN change timing: %s secs", tostring(time_2 - time_1))
    if (time_2 - time_1 > 105) and (time_2 - time_1 < 135) then
      -- Found it!

      if has_high_ttl then
        -- Many VIPs set IP TTL to 255, use it to increase the confidence level
          confidence_level = "high"
      end

      if has_timestamps then
        return "Possible NetScaler PPE TCP/IP stack (with timestamps enabled) detected (" .. confidence_level .. " confidence)"
      else
        return "Possible NetScaler PPE TCP/IP stack detected (" .. confidence_level .. " confidence)"
      end
    end
  end
end
