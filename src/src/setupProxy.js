module.exports = function (app) {
  app.disable("x-powered-by");
  app.set("host", "0.0.0.0");
};
