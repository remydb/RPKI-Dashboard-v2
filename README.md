RPKI Dashboard v2.0
=================

## Overview
After creating the original RPKI dashboard for my master's thesis I thought it would be fun to rewrite it from scratch.
Lately I've had a growing interest in the reasonably new "Go" language and things like NoSQL databases, javascript and object stores.
After some research and testing I decided to build version 2 of the RPKI dashboard in the following way:

-All backend processing is done using code written in Golang
-All data is stored in MongoDB
-The data for the frontend will be delivered by a daemon offering a REST API
-The frontend will (probably) be built using AngularJS


### Golang

I chose to do the bulk of the processing using Golang as the easy concurrency options it provides seemed quite useful for this project. Luckily, this has so far been proven right.
The old RPKI dashboard did the backend processing using a variety of bash and python scripts. The most time consuming part was validating each route using the validated ROA payload. With the old python script this could take up to an hour and a half or two hours. The same process performed using highly concurrent Golang code combined with a MongoDB backend shortened this time to about 3 to 4 minutes (using a beefy dual-quad-core server with 64Gb of ram and a pool of 1000 goroutines, my regular desktop pretty much dies with a pool of more than 20 goroutines).

### MongoDB

The reason I chose MongoDB over MySQL was the fact that a relational database is not really needed for this type of data and the BSON storage of MongoDB seems very well suited for storing a large list of internet routes along with some extra information on each route. The performance of MongoDB has also been quite good, with it keeping up with a large amount of queries, both inserts and show queries.

### Frontend

The frontend for version 1 of the RPKI dashboard was written in PHP and featured a number of pages which executed up to hundreds of queries for a single get request, which could result in load times of roughly 10 to 20 seconds. By using a Golang daemon with a RESTful HTTP API I hope to greatly speed up these page load times and make the dashboard a lot smoother as a whole. I have absolutely no experience creating such frontends, so I expect this to be quite a challenge!


## Progress

So far the backend is almost fully completed, the only part missing at the time of writing is the insertion of RIRs for each route. I'm just working on this project in my spare time to get more experience in writing Golang code and to get some experience with creating fancier, more dynamic frontends. There's no real timeframe for when this is going to be finished, but I hope to have it all completely done (and hopefully replace the current dashboard running at http://rpki.surfnet.nl) by this summer.