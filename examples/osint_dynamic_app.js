(function () {
  var codes = [102, 108, 97, 103, 123, 100, 121, 110, 97, 109, 105, 99, 95, 111, 115, 105, 110, 116, 125];
  var flag = String.fromCharCode.apply(String, codes);
  var seed = window.__intelSeed || {};
  var profile = document.getElementById("profile");
  var status = document.getElementById("status");
  if (!profile || !status) {
    return;
  }
  status.textContent = "Analyst profile ready.";
  profile.innerHTML = [
    "<p>Primary handle: " + (seed.handle || "@unknown") + "</p>",
    "<p>Mailbox: " + (seed.email || "unknown@example.org") + "</p>",
    "<p>Domain: " + (seed.domain || "example.org") + "</p>",
    "<p>Recovered token: " + flag + "</p>"
  ].join("");
})();
