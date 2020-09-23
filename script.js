function getPages(maxValue, numPerPage=500) {
  /**
   * Function designed to paginate results from the API,
   * to prevent calling too many results from the API, and 
   * using a default value of 500 (as told by the server) per page.
   * Will only return pages up to maxValue.
   * 
   * @params maxValue: The number of entries to stop at. Typically gotten by calling the /get-events endpoint and passing in EntryCount.
   * @params numPerPage: The number of entries to get per page.
   * @returns 2D Array of [from, to] pairs.
   */
  let pages = [];
  for (let i = 1; i < maxValue; i += numPerPage) {
    if (i + numPerPage < maxValue) pages.push([i, i+numPerPage-1]);
    else pages.push([i, maxValue]);
  }
  return pages;
}

async function getAuth () {
  /**
   * Used to get the key for the API.
   * Caches the key in the session once it has been called for.
   * 
   * @returns String API Key.
   */
  if (window.API_KEY) {
    return window.API_KEY;
  }
  return fetch('https://curly-surf-1c5a.cpaultill.workers.dev/?https://challenger.btbsecurity.com/auth',
    {
      method: 'get',
      //mode: 'no-cors',
    }
  )
  .then(response => response.text())
  .then(key => {
    // Cache resulting key if not already stored.
    window.API_KEY = key;
    return window.API_KEY
  }); 
}

async function getEvents (fromValue=null, toValue=null) {
  /**
   * Used to call the /get-events endpoint from the API.
   * 
   * Passing no params will result in none being passed to the API, 
   * so this is how it can be used to get the EntryCount.
   * 
   * Otherwise, if params exist, they are interpolated in to arguments 
   * and appended to the query.
   * 
   * @params fromValue: Starting entry inclusive to retrieve from /get-events endpoint.
   * @params toValue: Ending entry inclusive to retrieve from /get-events endpoint.
   * @returns JSON Retrieved Data as an Array of events or failure of Promise.
   */
  let toAppend = '';
  if (typeof fromValue === 'number' && typeof toValue === 'number') 
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
    // Use a proxy to deal with potential CORS issues.
    return fetch(`https://curly-surf-1c5a.cpaultill.workers.dev/?https://challenger.btbsecurity.com/get-events${toAppend}`,
    {
      method: 'get',
      //mode: 'no-cors',
      headers: new Headers({
        'Authorization': key,
      })
    })
    .then(res => res.json());
  }); 
}

function mapLoginState(state) {
  /**
   * Maps login states retrieved from API to the requested 
   * 'Logon-Success' when 'success' is detected in the event string,
   * 'Logon-Failure' otherwise.
   * 
   * @returns String
   */
  if (state.toLowerCase().includes('success')) {
    return 'Logon-Success';
  } else {
    return 'Logon-Failure';
  }
}

function mapEpochToReadableTime(epoch) {
  /**
   * Uses the epoch time retrieved from the endpoint (in seconds)
   * and converts to Javascript Date Format (milliseconds) so conversion of 
   * argument happens in function.
   * 
   * @returns String representation of epoch.
   */
  let d = new Date(epoch * 1000);
  return d.toUTCString();
}

function mapEmailToReadableAddress(email) {
  /**
   * Filters out any unecessary words and converts email to lowercase, removing whitespace after removing extra characters.
   * In this case, ':' is not a valid email identifier so we cut the string based on that character.
   * 
   * @params email: string identifier of user.
   * @returns String re-formatted for use in data normalization.
   */
  if (email.toLowerCase().includes('username is:')) {
    return email.substring(email.indexOf(':')+1).toLowerCase().trim();
  } else {
    return email.toLowerCase();
  }
}

function normalizeData(entry) {
  /**
   * Normalizes a /get-events endpoint log entry with the expected fields.
   * 
   * @params entry: A /get-events log entry.
   * @returns Object with requested fields normalized.
   */
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

function reduceUsers() {
  /**
   * Prepare a reduced version of the normalized data, for visualization purposes.
   * 
   */
  if (!window.NORMALIZED_DATA) return -1;
  window.USERS_REDUCED = window.NORMALIZED_DATA.reduce((accumulator, entry) => {
    if (!accumulator[entry.UserName]) {
      accumulator[entry.UserName] = {};
      accumulator[entry.UserName].Count = 0;
      accumulator[entry.UserName].LoginAttempts = [];
      accumulator[entry.UserName].LoginAttemptCounts = {
        success: 0,
        failure: 0,
      }
      accumulator[entry.UserName].TargetConnections = {}
    }
    accumulator[entry.UserName].Count ++;
    accumulator[entry.UserName].LoginAttempts.push({
      target: entry.Target,
      id: entry.AcmeApiId,
      ip: entry.SourceIp,
      action: entry.Action,
    });
    entry.Action === 'Logon-Success' ?
      accumulator[entry.UserName].LoginAttemptCounts.success ++ :
      accumulator[entry.UserName].LoginAttemptCounts.failure ++;
    return accumulator;
  }, new Object());
  return 1;
}

function reduceTargets() {
  /**
   * Prepare a reduced version of the normalized data, for visualization purposes.
   * 
   */
  if (!window.NORMALIZED_DATA) return -1;
  window.TARGETS_REDUCED = window.NORMALIZED_DATA.reduce((accumulator, entry) => {
    if (!accumulator[entry.Target]) {
      accumulator[entry.Target] = {};
      accumulator[entry.Target].Count = 0;
      accumulator[entry.Target].LoginAttempts = [];
    }
    accumulator[entry.Target].Count ++;
    accumulator[entry.Target].LoginAttempts.push({
      user: entry.UserName,
      id: entry.AcmeApiId,
      ip: entry.SourceIp,
      action: entry.action,
    });
    return accumulator;
  }, new Object());
}

function getPercentageSuccessFailure(loginAttemptCounts) {
  /**
   * Returns an array of successes to failure, based on their respective counts.
   * 
   * @params: an object with properties "success" and "failure"
   * @returns Array of [successPercentage, failurePercentage]
   */
  const {
    success,
    failure,
  } = loginAttemptCounts;
  return [
    (success / (success + failure) * 100).toFixed(2),
    (failure / (success + failure) * 100).toFixed(2),
  ]
}

function sortSetByLoginCount(objectToSort) {
  /**
   *  Sort item entries by those that have the highest interaction count, so we can make the graph.
   * 
   * @params objectToSort: an entry to sort containing the Count property.
   */
  if (!objectToSort) return -1;
  return Object.entries(objectToSort).sort((a, b) => a[1].Count > b[1].Count ? -1 : 1);
}

function createTargetBarGraph(data, selector, title) {
  /**
   * Create a d3 bar graph and display the data sent in!
   * 
   * @params data: the data array.
   * @params selector: the selector used to access the div the graph is held in.
   * @params title: the graph title.
   */
  var margin = {top: 30, right: 30, bottom: 140, left: 120},
    width = 460 - margin.left - margin.right,
    height = 400 - margin.top - margin.bottom;

  // append the svg object to the body of the page
  var svg = d3.select(`#${selector}`)
    .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
    .append("g")
      .attr("transform", "translate(" + margin.left + "," + margin.top + ")");


  // Add X axis 
  var x = d3.scaleBand()
    .range([0, width])
    .domain(data.map(d => d[0]))
    .padding(0.2);
  svg.append("g")
    .attr("transform", "translate(0," + height + ")")
    .call(d3.axisBottom(x))
    .selectAll("text")
      .attr("transform", "translate(-10,0)rotate(-45)")
      .style("color", "#184163")
      .style("text-anchor", "end");

  // Add Y axis
  var y = d3.scaleLinear()
    .domain([0, data[0][1].Count])
    .range([ height, 0]);
  svg.append("g")
    .call(d3.axisLeft(y));

  // Add rectangles
  svg.selectAll("mybar")
    .data(data)
    .enter()
    .append("rect")
      .attr("x", function(d) { return x(d[0]); })
      .attr("y", function(d) { return y(d[1].Count); })
      .attr("width", x.bandwidth())
      .attr("height", function(d) { return height - y(d[1].Count); })
      .attr("fill", "#4B8B91");

  // Add title
  svg.append("text")
    .attr("x", (width / 2))             
    .attr("y", 0 - (margin.top / 2))
    .attr("text-anchor", "middle")  
    .style("font-size", "16px") 
    .style("color", "#184163")
    .style("text-decoration", "underline")  
    .text(`${title}`);
}

async function driverCode() {
  /**
   * Main driver function, usually set to run on page load, and only once so as not to
   * overload the API server with requests. Stores resulting data in session variables.
   */
  const PER_PAGE = 500;
  getEvents(null, null).then(async value => {
    const pages = getPages(value.EntryCount, PER_PAGE);
    let temp = [];
    for (page of pages) {
      await getEvents(page[0], page[1]).then(events => temp.push(...events));
    }
    return temp;
  })
  .then(object => window.REQUESTED_DATA = object)
  .then(() => {
    window.NORMALIZED_DATA = window.REQUESTED_DATA.map(entry => normalizeData(entry));
  })
  .then(() => {
    /**
     * Construct a blob of data (data is too large to download directly via JSON in most cases.)
     * Convert blob to a url, and enable the link once the data has loaded and is ready for download.
     * Finally, link the data and create a descriptive file name (time of  current logs download.)
     * 
     * Does NOT download data automatically, as this can be sketchy, 
     * or not requested by the user if they simply want to view ther visualization.
     */
    const data = JSON.stringify(window.NORMALIZED_DATA);
    const blob = new Blob([data], {type:"application/json"});
    var url = URL.createObjectURL(blob);
    const a = document.querySelector("#download-link");
    const button = document.querySelector('#download');
    const status = document.querySelector("#status").innerHTML = "Data is ready for download. Click the button below to download the logs."
    a.setAttribute('href', url);
    a.setAttribute('download', `logs-${new Date(Date.now()).toISOString()}.json`);
    button.disabled = false;
  })
  .then(() => {
    /**
     * Play with data and get it into a nice format to display.
     * Create 2 bar graphs, and a table of data.
     */
    reduceTargets();
    reduceUsers();
    window.USERS_REDUCED_SORTED = sortSetByLoginCount(window.USERS_REDUCED);
    window.TARGETS_REDUCED_SORTED = sortSetByLoginCount(window.TARGETS_REDUCED);
    createTargetBarGraph(window.TARGETS_REDUCED_SORTED, 'target_dataviz', 'Number of Logins per Domain');
    createTargetBarGraph(window.USERS_REDUCED_SORTED.slice(0, 20), 'user_dataviz', 'Number of Logins Per User (Top 20)');
    let table = document.querySelector('#user-table');
    let h4 = document.querySelector("#user-table-description");
    window.USERS_REDUCED_SORTED.slice(0, 50).forEach((entry, i) => {
      let row = table.insertRow(i+1);
      const percentages = getPercentageSuccessFailure(entry[1].LoginAttemptCounts);
      row.insertCell(0).innerHTML = `${entry[0]}`;
      row.insertCell(1).innerHTML = `${entry[1].LoginAttemptCounts.success + entry[1].LoginAttemptCounts.failure}`;
      row.insertCell(2).innerHTML = `${percentages[0]}%`;
      row.insertCell(3).innerHTML = `${percentages[1]}%`;
    });
    table.style.display = "table";
    h4.style.display = "block";
  });
} 

driverCode();
