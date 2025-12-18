// server/index.js
import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "https://test-jwt-roan.vercel.app",
    credentials: true,
  })
);

// 메모리 기반 유저 저장소 (DB 대신 사용)
const users = [
  {
    id: "user-1",
    email: "test@example.com",
    password: "qwe123!!",
    name: "테스트 유저",
  },
];

// 메모리 기반 글 저장소
let postIdSeq = 1;
const posts = [];

const ACCESS_TOKEN_SECRET = "access-secret";
const REFRESH_TOKEN_SECRET = "refresh-secret";

const ACCESS_TOKEN_EXPIRES_IN = "10s";
const REFRESH_TOKEN_EXPIRES_IN = "30s";

function signAccessToken(userId) {
  return jwt.sign({ sub: userId }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

function signRefreshToken(userId) {
  return jwt.sign({ sub: userId }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRES_IN,
  });
}

// 토큰 쿠키 세팅 헬퍼
function setAuthCookies(res, userId) {
  const accessToken = signAccessToken(userId);
  const refreshToken = signRefreshToken(userId);

  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: true, // 실제 서비스에서는 true + HTTPS 권장
    sameSite: "none",
    path: "/",
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });

  return { accessToken, refreshToken };
}

app.get("/", (req, res) => {
  res.json("Hello, World");
});
// 회원가입
app.post("/auth/signup", (req, res) => {
  const { email, password, name } = req.body || {};

  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ message: "email, password, name 모두 필요합니다." });
  }

  const existing = users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ message: "이미 존재하는 이메일입니다." });
  }

  const newUser = {
    id: `user-${users.length + 1}`,
    email,
    password, // 데모용. 실제 서비스에서는 해시 필수.
    name,
  };

  users.push(newUser);
  setAuthCookies(res, newUser.id);

  return res.status(201).json({
    ok: true,
    user: {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
    },
  });
});

// 로그인
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: "email과 password가 필요합니다." });
  }

  const user = users.find((u) => u.email === email);
  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const { accessToken, refreshToken } = setAuthCookies(res, user.id);
  res.json({ accessToken, refreshToken });
});

// 인증 미들웨어 (access 만료 시 refresh로 재발급 후 통과)
function authMiddleware(req, res, next) {
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ message: "No token" });
  }

  // access token 먼저 검증
  if (accessToken) {
    try {
      const payload = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);
      req.user = { id: payload.sub };
      return next();
    } catch (e) {
      if (e.name !== "TokenExpiredError") {
        console.error("Access token verify error:", e);
        return res.status(401).json({ message: "Invalid token" });
      }
      console.log("Access token expired, trying refresh...");
    }
  }

  // access가 없거나 만료된 상태 → refresh 확인
  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token" });
  }

  try {
    const refreshPayload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = refreshPayload.sub;

    const user = users.find((u) => u.id === userId);
    if (!user) {
      res.clearCookie("access_token", { path: "/" });
      res.clearCookie("refresh_token", { path: "/" });
      return res
        .status(401)
        .json({ message: "User not found for refresh token" });
    }

    const newAccessToken = signAccessToken(userId);

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 15 * 60 * 1000, // 15분
    });

    req.user = { id: userId };
    return next();
  } catch (e) {
    console.error("Refresh token verify error:", e);

    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/" });

    return res.status(401).json({ message: "Invalid refresh token" });
  }
}

// 선택적 인증 미들웨어 (실패해도 401 없이 진행)
function optionalAuthMiddleware(req, res, next) {
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  if (!accessToken && !refreshToken) {
    return next();
  }

  if (accessToken) {
    try {
      const payload = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);
      req.user = { id: payload.sub };
      return next();
    } catch (e) {
      if (e.name !== "TokenExpiredError") {
        console.error("optionalAuth access verify error:", e);
        return next();
      }
      console.log("optionalAuth: access expired, trying refresh...");
    }
  }

  if (!refreshToken) {
    return next();
  }

  try {
    const refreshPayload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = refreshPayload.sub;

    const user = users.find((u) => u.id === userId);
    if (!user) {
      res.clearCookie("access_token", { path: "/" });
      res.clearCookie("refresh_token", { path: "/" });
      return next();
    }

    const newAccessToken = signAccessToken(userId);

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 15 * 60 * 1000, // 15분
    });

    req.user = { id: userId };
    return next();
  } catch (e) {
    console.error("optionalAuth refresh verify error:", e);

    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/" });
    return next();
  }
}

// 토큰 재발급 (별도 엔드포인트 사용 시)
app.post("/auth/refresh", (req, res) => {
  const { refreshToken } = req.body; // 또는 req.cookies.refresh_token 사용 가능

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token" });
  }

  try {
    const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = payload.sub;

    const user = users.find((u) => u.id === userId);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const newAccessToken = signAccessToken(userId);

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    return res.json({ accessToken: newAccessToken });
  } catch (e) {
    console.error("Refresh token verify error:", e);
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

// 현재 로그인한 유저 정보
app.get("/me", authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user?.id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
  });
});

// 로그아웃
app.post("/auth/logout", (req, res) => {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/" });
  res.json({ ok: true });
});

// 글 관련 API

// 글 작성 (인증된 사용자만)
app.post("/posts", authMiddleware, (req, res) => {
  const { title, content } = req.body || {};

  if (!title || !content) {
    return res.status(400).json({ message: "title과 content는 필수입니다." });
  }

  const authorId = req.user.id;

  const newPost = {
    id: postIdSeq++,
    title,
    content,
    authorId,
    createdAt: new Date().toISOString(),
  };

  posts.unshift(newPost);

  return res.status(201).json({
    ok: true,
    post: newPost,
  });
});

// 글 목록
app.get("/posts", (req, res) => {
  const postSummaries = posts.map((post) => {
    const author = users.find((u) => u.id === post.authorId);
    return {
      id: post.id,
      title: post.title,
      preview:
        post.content.length > 60
          ? post.content.slice(0, 60) + "..."
          : post.content,
      authorName: author?.name || "알 수 없음",
      createdAt: post.createdAt,
    };
  });

  res.json(postSummaries);
});

app.listen(4000, () => {
  console.log("Auth server running on http://localhost:4000");
});
