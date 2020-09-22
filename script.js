

function getPages(maxValue, numPerPage=500) {
  let pages = [];
  for (let i = 1; i < maxValue; i += numPerPage) {
    if (i + numPerPage < maxValue) pages.push([i, i+numPerPage-1]);
    else pages.push([i, maxValue]);
  }
  return pages;
}

async function getAuth () {
  if (window.API_KEY) return window.API_KEY;
  return fetch('https://cors-anywhere.herokuapp.com/https://challenger.btbsecurity.com/auth')
  .then(response => response.text())
  .then(key => {
    window.API_KEY = key;
    return window.API_KEY
  }); 
}

async function getEvents (fromValue=null, toValue=null) {
  let toAppend = '';
  if (typeof fromValue === 'number' && 
      typeof toValue === 'number') 
  {
    if (fromValue > 0 && fromValue < toValue) {
      toAppend = `?&from=${fromValue}&to=${toValue}`;
    }
  } else if (typeof fromValue === 'number' && !toValue) {
     if (fromValue > 0) {
       toAppend = `?&from=${fromValue}`;
     }
  }
  return getAuth().then(key => {
    //if (window.API_KEY) return window.API_KEY;
    return fetch(`https://cors-anywhere.herokuapp.com/https://challenger.btbsecurity.com/get-events${toAppend}`,
    {
      method: 'get',
      headers: new Headers({
        'Authorization': key,
      })
    })
    .then(res => res.json());
    //.then(data => console.log(data.EntryCount));
  }); 
}

function mapLoginState(state) {
  if (state.toLowerCase().includes('success')) {
    return 'Logon-Success';
  } else {
    return 'Logon-Failure';
  }
}

function mapEpochToReadableTime(epoch) {
  let d = new Date(epoch * 1000);
  return d.toUTCString();
}

function mapEmailToReadableAddress(email) {
  if (email.toLowerCase().includes('username is:')) {
    return email.slice(email.indexOf(':')).toLowerCase().strip();
  } else {
    return email.toLowerCase();
  }
}

function normalizeData(entry) {
  const {
    DateTimeAndStuff,
    EVENT_0_ACTION,
    id,
    ips,
    target,
    user_Name,
  } = entry;
  return {
    AcmeApiId: id,
    UserName: mapEmailToReadableAddress(user_Name),
    SourceIp: ips[0],
    Target: target,
    Action: mapLoginState(EVENT_0_ACTION),
    EventTime: mapEpochToReadableTime(DateTimeAndStuff),
  };
} 

async function getRequestedData() {
  const PER_PAGE = 500;
  getEvents(null, null).then(async value => {
    const pages = getPages(value.EntryCount, PER_PAGE);
    let temp = [];
    for (page of pages) {
      await getEvents(page[0], page[1]).then(events => temp.push(...events));
    }
    return temp;
  })
  .then(retVal => object = retVal)
  .then(object => window.REQUESTED_DATA = object);
} 
//driverCode();

//getEvents(null, null).then(value => getEvents(1, value.EntryCount).then(value => console.log(value)));
//getEvents(1).then(value => console.log(value));
//getEvents(51, 100).then(value => console.log(value));

//// TODO: Implement Paging 500 at a time.
//// TODO: Driver Code.
//// TODO: Fun vis? Show off some css.
