# SQL Framework

This is a project I worked on many moons ago. It's a framework for executing blind SQL attacks.<br />
The project is written in PHP for no particular reason.

## Description

The approach of this framework to blind sql injection is to use page caching.<br />
Normally, when you execute blind sql injection, you don't know whether your query succeeded or not.<br />
There is no response from the target, as errors have been silenced.<br />
<br/>
What this approach does, instead, is to query specific pages to get the answer to specific queries.<br />
For example, support you have a site called `http://www.target.com/` with a vulnerable blind sql injection at `http://www.target.com/news.php?id=1`<br />
where the 'id' parameter is vulnerable to queries as in the following.

```php
$query = "SELECT * FROM tblNews WHERE id = ".$_REQUEST_['id'];
$result = @mysql_query($query);
```

As you can see, the `id` parameter is used in the query as-is, without any validation.
Because of the `@` character, no errors will be displaye if the query is invalid.

To exploit this vulnerability, we can write a blind sql injection asking the web server to return a specific page depending on the output of the query.

## Features

- 3 different attacking methods
    1. Normal
    2. Smart
    3. Caching
- Pre-generated queries




