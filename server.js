const express = require('express')
const cors=require('cors')
const mysql=require('mysql2/promise')
const bcrypt=require('bcrypt')
const {WebSocketServer}=require('ws')
const path=require('node:path')

// 프로젝트 루트에서 실행해도 서버 전용 환경 변수를 정확히 불러옵니다.
require('dotenv').config({path:path.join(__dirname,'.env')})

const app=express()

app.use(cors({
    // 환경변수 이름은 대소문자를 구분하는 배포 환경에서도 동일하게 맞춥니다.
    origin: process.env.FRONT_URL
}))

app.use(express.json())

const db=mysql.createPool({
    host: process.env.DB_HOST,
    port:Number(process.env.DB_PORT||3306),
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DB_NAME,
    ssl:{
        rejectUnauthorized: false
    }
})

app.get('/db-test',async(req,res)=>{
    try{
        await db.query('select 1')
        res.json({
            message:'DB연결성공'
        })
        console.log('DB연결 성공')
    }catch(err){
        console.log('DB연결 실패',err)
         res.status(500).json({
            message:'DB연결실패'
        })
    }
})


//회원가입 이제 시작함 ㄱㄱ
app.post('/signup',async(req,res)=>{
    const {name, username, password}=req.body
    if(!name||!username||!password){
        return res.status(400).json({
            message: '값이 없습니다'
        })
    }
    try{
       //같은 아이디가 있는지 확인
       const [rows]=await db.execute('select * from members where username=?',[username])
       if(rows.length>0){
        return res.status(400).json({
            message:'이미 사용중인 아이디 입니다'
        })
       }

       const hash=await bcrypt.hash(password, 10)

       await db.execute(`insert into members (name, username, password, provider) values (?,?,?,?)`, [name, username, hash, "local"])
       res.json({
        message:'회원가입 성공'
       })
    }catch(err){
        console.log(err)
        // DB 오류를 성공(200)으로 오해하지 않도록 500 상태를 반환합니다.
        res.status(500).json({
        message:'회원가입 실패 ㅠㅠㅠ'
       })
    }
})

//로그인으로 받기
app.post('/login',async(req,res)=>{
    const {username, password}=req.body
    if(!username||!password){
        return res.status(400).json({
            message:'아이디와 비밀번호를 입력해 주세요'
        })
    }
    try{
        const [rows]=await db.execute('select * from members where username=?',[username])
        if(rows.length===0){
            return res.status(400).json({
                message:'아이디가 없습니다'
            })
        }
        const user=rows[0]
        const ok=await bcrypt.compare(password, user.password)
        if(!ok){
            return res.status(400).json({
                message:'비밀번호가 틀렸습니다'
            })
        }

        res.json({
            message:'로그인에 성공했습니다',
            user:{
                id: user.id,
                name: user.name,
                username: user.username
            }
        })
    }catch(err){
        console.log(err)
        res.status(500).json({
            message:'로그인 실패'
        })
    }
})


/*소셜 로그인---------
    사용자가 네이버나 카카오로그인을 클릭함-> express서버의 /auth/kakao등으로 이동함 
    ->실제 express서버가 할 일은 각각 네이버나 카카오 로그인 페이지로 이동 ->
    사용자가 로그인을 함-> 네이버나 카카오가 콜백주소로 ((코드))를 전달 ***코드: 임시 교환권***
    ---> express서버가 코드를(임시교환권을) 네이버나 카카오에게 다시 줌 
    --> 허가증을 줌(네이버나 카카오가) 나에게 !!access_token을 난 받음express서버에게 다시 줌!!(임시 허가증 같은 것)
      express서버가 액세스 토큰을 보여주고 사용자 정보를 요청-> 네이버나 카카오가 이름, 이메일 등을 제공
      --> 네 서버에 (DB, mysql)에 기존 회원이 있는지 확인하고 없으면 회원을 추가
      
      ---> 최종적으로 로그인이 됨(express서버=내서버 가 로그인을 해줌)*/

//-----------네이버 카카오 받아치는--------

//---------------아래는 카카오---------------------------------
app.get('/auth/kakao',(req,res)=>{
    const url ="https://kauth.kakao.com/oauth/authorize" +
        `?client_id=${process.env.KAKAO_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(
            process.env.KAKAO_REDIRECT_URI
        )}` + "&response_type=code";

    // 카카오 로그인 화면으로 이동
    res.redirect(url);
})
app.get( "/auth/kakao/callback",  async (req, res) => {
        const code = req.query.code;
        try {
            // 카카오 Access Token 요청
            const tokenResponse = await fetch( "https://kauth.kakao.com/oauth/token", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    body: new URLSearchParams({
                        grant_type: "authorization_code",
                        client_id:  process.env.KAKAO_CLIENT_ID,
                        client_secret:  process.env.KAKAO_CLIENT_SECRET,
                        redirect_uri: process.env.KAKAO_REDIRECT_URI,
                        code
                    })
                }
            );
            const tokenData = await tokenResponse.json();

            // 토큰을 가지고 카카오 회원정보 요청
            const userResponse = await fetch( "https://kapi.kakao.com/v2/user/me",  {
                    headers: {
                        Authorization: `Bearer ${tokenData.access_token}`
                    }
                }
            );
            const kakaoUser =  await userResponse.json();
            const socialId = String(kakaoUser.id);
            const name =  kakaoUser.properties?.nickname || "카카오 사용자";

            // 이미 가입한 카카오 회원인지 확인
            const [users] = await db.execute(
                `SELECT * FROM members   WHERE provider = ?  AND social_id = ?`,
                [  "kakao",  socialId  ]
            );


            // 처음 로그인한 회원
            if (users.length === 0) {
                // 회원정보 저장
                await db.execute(
                    `INSERT INTO members   (name, provider, social_id)   VALUES (?, ?, ?)`,
                    [  name,  "kakao",  socialId  ]
                );
            }
            // Next 채팅 화면으로 이동
            res.redirect(
                `${process.env.FRONT_URL}/chat?name=${encodeURIComponent(
                    name
                )}`
            );
        } catch (err) {
            console.log(err);
            res.status(500).send(
                "카카오 로그인 실패"
            );
        }
    }
);
//카카오 로그인 페이지로 감-> 로그인 완료 후에 다시 돌아옴 내 로컬로 (콜백주소)/code를 받은 상태임->받은 code를 카카오에게 토큰을 받아야 함
//


//---------아래는 네이버------------------------------

app.get('/auth/naver',(req,res)=>{
      const state = "next-project";
    const url ="https://nid.naver.com/oauth2.0/authorize" +
        "?response_type=code" +
        `&client_id=${process.env.NAVER_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(
            process.env.NAVER_REDIRECT_URI
        )}` + `&state=${state}`;

    // 네이버 로그인 화면으로 이동
    res.redirect(url);
})
//--------네이버 콜백-------
app.get( "/auth/naver/callback",  async (req, res) => {
        const code = req.query.code;
        const state = req.query.state;
        try {
            // 네이버 Access Token 요청
            const tokenUrl = "https://nid.naver.com/oauth2.0/token" +
                "?grant_type=authorization_code" +
                `&client_id=${process.env.NAVER_CLIENT_ID}` +
                `&client_secret=${process.env.NAVER_CLIENT_SECRET}` +
                `&code=${code}` + `&state=${state}`;
            const tokenResponse = await fetch(tokenUrl);
            const tokenData =  await tokenResponse.json();


            // 네이버 회원정보 요청
            const userResponse = await fetch( "https://openapi.naver.com/v1/nid/me",
                {
                    headers: {
                        Authorization: `Bearer ${tokenData.access_token}`
                    }
                }
            );
            const naverData =   await userResponse.json();


            const socialId = String( naverData.response.id );
            const name = naverData.response.nickname || naverData.response.name || "네이버 사용자";

            // 이미 가입한 회원인지 확인
            const [users] = await db.execute(
                `SELECT * FROM members    WHERE provider = ?   AND social_id = ?`,
                    [ "naver", socialId ]
            );


            // 처음 로그인한 회원
            if (users.length === 0) {
                // 회원정보 저장
                await db.execute( `INSERT INTO members (name, provider, social_id) VALUES (?, ?, ?)`,
                    [  name, "naver", socialId  ]
                );
            }
            // 채팅 화면으로 이동
            res.redirect(`${process.env.FRONT_URL}/chat?name=${encodeURIComponent( name )}` );
        } catch (err) {
            console.log(err);
            res.status(500).send("네이버 로그인 실패" );
        }
    }
);




/*웹소켓::: 브라우저 와 서버가ㅏ 연결을 계속 유지하면서 서로 데이터를 주고 받는 통신 방식을 이야기 함 .
기존의 우리가 아는 것은 fetch()밖에 없음, fetch()는 http://localhost:4000.login 이런 식으로 /fetch의 통신 방식은 
요청을 하고 응답을 하면 통신이 끝남. 
next 유저a->웹소켓->서버->웹소켓->next 유저b ::a,b유저가 서로 웹소켓을 통하여 주고 받음
브로드캐스트:: A가 '안녕'을 입력하면 서버에 접속된 B, C가 동시에 '안녕'이라는 글자를 볼 수 있다

프로그램 구현은 아래---*/


// const wss=new WebSocketServer({server})
// //사용하는 방법
// wss.on("connection",(socket)=>{
//     console.log('채팅접속')
//     socket.on("message",(message)=>{
//         const data=message.toString()
//         wss.clients.forEach((client)=>{
//             if(client.readyState===1){
//                 client.send(data)
//             }
//         })
//     })
//     socket.on("close",()=>{
//         console.log("채팅종료")
//     })
// })
const http = require("http");

// const app = express();

const server = http.createServer(app);

const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  console.log("웹소켓 연결됨");

  ws.on("message", (message) => {
    const data=message.toString();
    wss.clients.forEach((client)=>{
      if(client.readyState===1){
        client.send(data);
      }
    });
  });
});

const PORT = process.env.PORT || 4000;

// Express 요청과 웹소켓 연결을 하나의 HTTP 서버와 포트에서 함께 처리합니다.
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
