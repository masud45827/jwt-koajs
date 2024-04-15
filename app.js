const Koa = require("koa");
const json = require("koa-json");
const mongoose = require("mongoose");
const KoaRouter = require("koa-router");
const dotenv = require("dotenv");
const bodyParser = require("koa-bodyparser");
const Model = require("./model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = new Koa();
const router = new KoaRouter();

require("dotenv").config();
mongoose
  .connect(process.env.MONGO_URL, {})
  .then(() => {
    console.log("database connected");
  })
  .catch((error) => {
    console.error("Error connecting to database:", error);
});

app.use(json());
app.use(bodyParser());


// signup route
router.post("/signup", async (ctx) => {
  const { username, password } = ctx.request.body;
  const hashPassword = await bcrypt.hash(password, 10);
  const newUser = new Model({ username, password: hashPassword });
  const res = await newUser.save();
  console.log(res);
  ctx.status = 201; // Created
  ctx.body = res;
});


// login route
router.post("/login", async (ctx) => {
  const { username, password } = ctx.request.body;
  const user = await Model.find({ username:username });
  console.log(user);
  if (user && user.length > 0) {
    const isValidPassword = await bcrypt.compare(password, user[0].password);
    if (isValidPassword) {
      const token = jwt.sign(
        {
          username: user[0].username,
          userId: user[0]._id,
        },
        process.env.JWT_SECRET,{
            expiresIn:'1h'
        }
      );
      ctx.status = 200;
      ctx.body = token;
    } else {
      ctx.status = 401;
      ctx.body = "authentication failed";
    }
  } else {
    ctx.status = 401;
    ctx.body = "authentication failed";
  }
});


// token verification function
const verifyToken = async (ctx, next) => {
    const token = ctx.request.headers.authorization;
    if (!token) {
      ctx.status = 401; 
      ctx.body = { error: 'No token provided' };
      return;
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      await next();
    } catch (error) {
      ctx.status = 401; 
      ctx.body = { error: 'Invalid token' };
    }
  };

  //protected route
  router.get('/all_user', verifyToken, async (ctx) => {
      const data = await Model.find();
      ctx.body = data;
   
  });

app.use(router.routes());
app.use(router.allowedMethods());

const port = 8000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
