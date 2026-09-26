// The date and time functions of a PAC script, on top of the engine's Date.
// `__gatirNow()` is the current time in milliseconds, so tests can fix it.

(function (global) {
  "use strict";

  var DAYS = { SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6 };
  var MONTHS = { JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4, JUN: 5, JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11 };

  function now() {
    return new Date(global.__gatirNow());
  }

  // Whether the last argument asks for GMT; returns the arguments without it.
  function split(args) {
    var list = Array.prototype.slice.call(args);
    var gmt = list.length > 0 && String(list[list.length - 1]).toUpperCase() === "GMT";
    if (gmt) list.pop();
    return { args: list, gmt: gmt };
  }

  function name(table, value) {
    var key = String(value).toUpperCase();
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : -1;
  }

  function number(value) {
    var n = typeof value === "number" ? value : parseInt(value, 10);
    return isNaN(n) ? -1 : n;
  }

  // Whether `value` lies in [from, to], where a range that runs backwards
  // wraps around (SAT..MON, or 22:00..06:00).
  function within(value, from, to) {
    return from <= to ? from <= value && value <= to : value >= from || value <= to;
  }

  global.weekdayRange = function () {
    var s = split(arguments);
    if (s.args.length < 1 || s.args.length > 2) return false;
    var d = now();
    var today = s.gmt ? d.getUTCDay() : d.getDay();
    var from = name(DAYS, s.args[0]);
    var to = s.args.length === 2 ? name(DAYS, s.args[1]) : from;
    if (from < 0 || to < 0) return false;
    return within(today, from, to);
  };

  global.timeRange = function () {
    var s = split(arguments);
    var a = s.args.map(number);
    var d = now();
    var h = s.gmt ? d.getUTCHours() : d.getHours();
    var m = s.gmt ? d.getUTCMinutes() : d.getMinutes();
    var sec = s.gmt ? d.getUTCSeconds() : d.getSeconds();
    var t = (h * 60 + m) * 60 + sec;
    var from, to;
    for (var i = 0; i < a.length; i++) if (a[i] < 0) return false;

    if (a.length === 1) {
      // The whole of that hour.
      from = a[0] * 3600;
      to = from + 3599;
    } else if (a.length === 2) {
      // From the start of the first hour to the end of the second.
      from = a[0] * 3600;
      to = a[1] * 3600 + 3599;
    } else if (a.length === 4) {
      from = (a[0] * 60 + a[1]) * 60;
      to = (a[2] * 60 + a[3]) * 60 + 59;
    } else if (a.length === 6) {
      from = (a[0] * 60 + a[1]) * 60 + a[2];
      to = (a[3] * 60 + a[4]) * 60 + a[5];
    } else {
      return false;
    }
    return within(t, from, to);
  };

  global.dateRange = function () {
    var s = split(arguments);
    var args = s.args;
    if (args.length < 1) return false;
    var d = now();
    var year = s.gmt ? d.getUTCFullYear() : d.getFullYear();
    var month = s.gmt ? d.getUTCMonth() : d.getMonth();
    var day = s.gmt ? d.getUTCDate() : d.getDate();

    // What an argument stands for: a month name, a day (1 to 31) or a year.
    function part(value) {
      var m = name(MONTHS, value);
      if (m >= 0) return { month: m };
      var n = number(value);
      if (n < 0) return null;
      return n < 32 ? { day: n } : { year: n };
    }

    if (args.length === 1) {
      var only = part(args[0]);
      if (!only) return false;
      if (only.month !== undefined) return month === only.month;
      if (only.day !== undefined) return day === only.day;
      return year === only.year;
    }
    if (args.length % 2 !== 0) return false;

    var half = args.length >> 1;
    var start = { year: year, month: 0, day: 1 };
    var end = { year: year, month: 11, day: 31 };
    var seen = { start: {}, end: {} };
    for (var i = 0; i < args.length; i++) {
      var p = part(args[i]);
      if (!p) return false;
      var target = i < half ? start : end;
      var marks = i < half ? seen.start : seen.end;
      for (var key in p) {
        target[key] = p[key];
        marks[key] = true;
      }
    }

    // A day range with no month ("1" to "15") means those days of this month.
    if (args.length === 2 && seen.start.day && seen.end.day) {
      start.month = end.month = month;
    }
    // An end with a month but no day is the last day of that month.
    if (!seen.end.day) {
      end.day = new Date(Date.UTC(end.year, end.month + 1, 0)).getUTCDate();
    }
    // A start or end with no year is in this year.
    function dayKey(x) {
      return (x.year * 100 + x.month) * 100 + x.day;
    }
    return within(dayKey({ year: year, month: month, day: day }), dayKey(start), dayKey(end));
  };

  global.getClientVersion = function () {
    return "1.0";
  };
})(this);
