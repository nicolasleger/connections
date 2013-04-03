#!/usr/bin/env ruby

require 'open-uri'
require 'net/http'
require 'nokogiri'

class IpLookupService
  def query(ip)
    self.class::QUERY_URL.call(ip)
  end
end

class Utrace < IpLookupService
  QUERY_URL = lambda { |ip| return "http://www.utrace.de/?query=#{ip}" }

  def get_data(ip)
    data = { ip: ip }

    uri = URI(query(ip))
    html = Net::HTTP.get(uri)

    # Get data from Javascript and unescape it.
    raw_text_data = html[/var txt = "(.*)";/i, 1].gsub('\\', '')
    dom_text_data = Nokogiri::HTML(raw_text_data)
    dom_data = dom_text_data.css('.standard')
    if dom_data.any? and dom_data[5] and dom_data[8]
      data.merge!({
        provider: dom_data[5].css('a').first.inner_text.strip,
        location: dom_data[8].inner_text.strip
      })
    end

    geo_data = html.match(/ GLatLng\((-?[0-9]+\.[0-9]+), (-?[0-9]+\.[0-9]+)\);/)
    data.merge!({ latitude: geo_data[1], longitude: geo_data[2] }) if geo_data

    data
  end
end

class WhatIsMyIpAddress < IpLookupService
  QUERY_URL = lambda { |ip| return "http://whatismyipaddress.com/ip/#{ip}" }

  def get_data(ip)
    data = { ip: ip }

    uri = URI(query(ip))
    html = Net::HTTP.get(uri)
    dom = Nokogiri::HTML(html)
    dom_data = dom.css('tr')
    dom_data.each do |field|
      key = field.css('th').first.inner_text.strip.downcase[0...-1]
      data[key.gsub(' ', '_').to_sym] = field.css('td').first.inner_text.strip
    end

    data
  end
end

trusted_ips = [
  '127.0.0.1'
]
trusted_ips_regex = [
  /^192\.168\./,
]

connections = {}
utrace = Utrace.new
wimia = WhatIsMyIpAddress.new

netstat = `netstat -n | grep "ESTABLISHED"`
netstat.scan(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+)/) do |ip, port|
  if (not trusted_ips.include?(ip)) and (not connections.include?(ip))
    skipped = false
    trusted_ips_regex.each do |regex|
      if ip.match(regex)
        skipped = true
        break
      end
    end

    unless skipped
      connections[ip] = utrace.get_data(ip)
      connections[ip].merge!(wimia.get_data(ip))
      connections[ip][:port] = port
    end
  end
end

if ARGV.any?
  keys = ARGV.map(&:to_sym)
  puts connections.values.map { |data|
    data.select { |k, v| keys.include?(k) }
  }.join("\n\n")
else
  puts connections.values.join("\n\n")
end