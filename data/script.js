{{ define "script.js" }}

// Set Cookie passing Name, value, days in expire
function cookie_set(name,value,expire_days){
var cookie_name = name;
var expire_date=new Date();
expire_date.setDate(expire_date.getDate() + expire_days);
var cookie_value=escape(value) + ((expire_days===null) ? "" : "; expires="+expire_date.toUTCString() + "; path=/" );
document.cookie=cookie_name + "=" + cookie_value;
}

// Retrieve a cookie by name
function cookie_get(cookie_name){
var i,x,y,cookie=document.cookie.split(";");
for (i=0;i<cookie.length;i++) {
   x=cookie[i].substr(0,cookie[i].indexOf("="));
   y=cookie[i].substr(cookie[i].indexOf("=")+1);
   x=x.replace(/^\s+|\s+$/g,"");
   if (x==cookie_name)
     {
       return unescape(y);
     }
 }
}


// Filter the folder-list, and persist that section
function filterMailbox() {
var input = document.getElementById('filter');
var filter = input.value.toUpperCase();
var lis = document.getElementsByClassName('folder');
for (var i = 0; i < lis.length; i++) {
 var name = lis[i].innerHTML;
 if (name.toUpperCase().indexOf(filter) >= 0) {
   lis[i].style.display = 'list-item';
 } else {
   lis[i].style.display = 'none';
 }
}
cookie_set( "filter", input.value );
}

// React to changes.
var input = document.getElementById('filter');
input.onkeyup = filterMailbox;

// On page-load handle any cookie for persistent filtering.
var existing = cookie_get( "filter" );
if ( existing ) {
  input.value = existing
  filterMailbox();
}
{{ end }}
