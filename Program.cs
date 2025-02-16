using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace TestWork
{
    class Program
    {
        private static readonly string connectionString = "Server=localhost;Database=Avito;Trusted_Connection=True;";
        private static readonly string jwtSecretKey = "MySuperSecretKey1234567890!@#$%^&*()_+=-0987654321";

        static void Main()
        {
            Console.WriteLine("[SERVER] Запуск сервера...");

            string url = "http://localhost:8080/";
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add(url);
            listener.Start();
            Console.WriteLine($"[SERVER] Сервер запущен на {url}");

            while (true)
            {
                HttpListenerContext context = listener.GetContext();
                Task.Run(() => HandleRequest(context));
            }
        }

        static async void HandleRequest(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;
            response.ContentEncoding = Encoding.UTF8;
            response.ContentType = "application/json";

            // Декодируем URL-адрес
            string decodedUrl = Uri.UnescapeDataString(request.Url.AbsolutePath);
            Console.WriteLine($"[SERVER] Получен запрос: {request.HttpMethod} {decodedUrl}");

            byte[] buffer = null; // Объявляем переменную buffer на уровне метода

            try
            {
                if (request.HttpMethod == "POST" && decodedUrl == "/api/auth")
                {
                    await HandleAuthRequest(request, response);
                }
                else if (request.HttpMethod == "POST" && decodedUrl == "/api/sendCoin")
                {
                    await HandleSendCoinRequest(request, response);
                }
                else if (request.HttpMethod == "POST" && decodedUrl == "/api/register")
                {
                    await HandleRegisterRequest(request, response);
                }
                else if (request.HttpMethod == "GET" && decodedUrl.StartsWith("/api/купить/"))
                {
                    await HandlePurchaseRequest(request, response);
                }
                else if (request.HttpMethod == "GET" && decodedUrl == "/api/history")
                {
                    await HandleHistoryRequest(request, response);
                }
                else
                {
                    response.StatusCode = 404;
                    buffer = Encoding.UTF8.GetBytes("{\"error\": \"Not Found\"}");
                    await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    Console.WriteLine("[SERVER] Ошибка: Маршрут не найден");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVER] Ошибка: {ex.Message}");
                response.StatusCode = 500;
                buffer = Encoding.UTF8.GetBytes("{\"error\": \"Internal Server Error\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            }

            response.OutputStream.Close();
        }

        private static async Task HandleAuthRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
            {
                string requestBody = await reader.ReadToEndAsync();
                Console.WriteLine($"[SERVER] Тело запроса: {requestBody}");

                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var authRequest = JsonSerializer.Deserialize<AuthRequest>(requestBody, options);

                if (authRequest != null)
                {
                    string hashedPassword = HashPassword(authRequest.Password);
                    bool userExists = ValidateUser(authRequest.Username, hashedPassword, out int userId, out int balance, out string error);

                    if (userExists)
                    {
                        string token = GenerateJwtToken(userId, authRequest.Username);
                        var responseBody = JsonSerializer.Serialize(new { token, balance });

                        byte[] buffer = Encoding.UTF8.GetBytes(responseBody);
                        response.StatusCode = 200;
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine("[SERVER] Авторизация успешна!");
                    }
                    else
                    {
                        byte[] buffer = Encoding.UTF8.GetBytes($"{{\"error\": \"{error}\"}}");
                        response.StatusCode = 401;
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine($"[SERVER] Ошибка авторизации! {error}");
                    }
                }
            }
        }

        private static async Task HandleSendCoinRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            // Получаем токен из заголовка
            string token = request.Headers["Authorization"]?.Replace("Bearer ", "").Trim();
            Console.WriteLine($"[SERVER] Полученный токен: {token}");

            if (string.IsNullOrEmpty(token))
            {
                response.StatusCode = 401;
                byte[] buffer = Encoding.UTF8.GetBytes("{\"error\": \"Токен отсутствует\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Токен отсутствует");
                return;
            }

            // Валидируем токен
            if (!ValidateJwtToken(token, out int senderId, out string senderUsername))
            {
                response.StatusCode = 401;
                byte[] buffer = Encoding.UTF8.GetBytes("{\"error\": \"Неверный токен\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Неверный токен");
                return;
            }

            // Читаем тело запроса
            using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
            {
                string requestBody = await reader.ReadToEndAsync();
                Console.WriteLine($"[SERVER] Тело запроса: {requestBody}");

                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var sendCoinRequest = JsonSerializer.Deserialize<SendCoinRequest>(requestBody, options);

                if (sendCoinRequest != null)
                {
                    // Отправляем монетки
                    bool success = SendCoins(senderId, sendCoinRequest.ToUser, sendCoinRequest.Amount, out string error);

                    if (success)
                    {
                        response.StatusCode = 200;
                        byte[] buffer = Encoding.UTF8.GetBytes("{\"message\": \"Coins sent successfully\"}");
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine("[SERVER] Монеты успешно отправлены!");
                    }
                    else
                    {
                        response.StatusCode = 400;
                        byte[] buffer = Encoding.UTF8.GetBytes($"{{\"error\": \"{error}\"}}");
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine($"[SERVER] Ошибка: {error}");
                    }
                }
            }
        }

        private static async Task HandleRegisterRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
            {
                string requestBody = await reader.ReadToEndAsync();
                Console.WriteLine($"[SERVER] Тело запроса: {requestBody}");

                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var registerRequest = JsonSerializer.Deserialize<RegisterRequest>(requestBody, options);

                if (registerRequest != null)
                {
                    bool success = RegisterUser(registerRequest.Username, registerRequest.Password, out string error);

                    if (success)
                    {
                        response.StatusCode = 200;
                        byte[] buffer = Encoding.UTF8.GetBytes("{\"message\": \"User registered successfully\"}");
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine("[SERVER] Пользователь успешно зарегистрирован!");
                    }
                    else
                    {
                        response.StatusCode = 400;
                        byte[] buffer = Encoding.UTF8.GetBytes($"{{\"error\": \"{error}\"}}");
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        Console.WriteLine($"[SERVER] Ошибка: {error}");
                    }
                }
            }
        }

        private static async Task HandlePurchaseRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            // Получаем токен из заголовка
            string token = request.Headers["Authorization"]?.Replace("Bearer ", "").Trim();
            Console.WriteLine($"[SERVER] Полученный токен: {token}");

            if (string.IsNullOrEmpty(token))
            {
                response.StatusCode = 401;
                byte[] buffer = Encoding.UTF8.GetBytes("{\"error\": \"Токен отсутствует\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Токен отсутствует");
                return;
            }

            // Валидируем токен
            if (!ValidateJwtToken(token, out int userId, out string username))
            {
                response.StatusCode = 401;
                byte[] buffer = Encoding.UTF8.GetBytes("{\"error\": \"Неверный токен\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Неверный токен");
                return;
            }

            // Получаем название товара из URL
            string decodedUrl = Uri.UnescapeDataString(request.Url.AbsolutePath);
            string itemName = decodedUrl.Split('/').Last();
            Console.WriteLine($"[SERVER] Пользователь {username} пытается купить товар: {itemName}");

            // Покупаем товар
            bool success = PurchaseItem(userId, itemName, out string error);

            if (success)
            {
                response.StatusCode = 200;
                byte[] buffer = Encoding.UTF8.GetBytes("{\"message\": \"Товар успешно куплен\"}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine("[SERVER] Товар успешно куплен!");
            }
            else
            {
                response.StatusCode = 400;
                byte[] buffer = Encoding.UTF8.GetBytes($"{{\"error\": \"{error}\"}}");
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                Console.WriteLine($"[SERVER] Ошибка: {error}");
            }
        }

        private static async Task HandleHistoryRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            // Получаем токен из заголовка
            string token = request.Headers["Authorization"]?.Replace("Bearer ", "").Trim();
            Console.WriteLine($"[SERVER] Полученный токен: {token}");

            if (string.IsNullOrEmpty(token))
            {
                response.StatusCode = 401;
                byte[] errorBuffer = Encoding.UTF8.GetBytes("{\"error\": \"Токен отсутствует\"}");
                await response.OutputStream.WriteAsync(errorBuffer, 0, errorBuffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Токен отсутствует");
                return;
            }

            // Валидируем токен
            if (!ValidateJwtToken(token, out int userId, out string username))
            {
                response.StatusCode = 401;
                byte[] invalidTokenBuffer = Encoding.UTF8.GetBytes("{\"error\": \"Неверный токен\"}");
                await response.OutputStream.WriteAsync(invalidTokenBuffer, 0, invalidTokenBuffer.Length);
                Console.WriteLine("[SERVER] Ошибка: Неверный токен");
                return;
            }

            // Получаем историю транзакций и покупок
            var history = GetUserHistory(userId);

            // Возвращаем данные в формате JSON
            var responseBody = JsonSerializer.Serialize(history);
            byte[] responseBuffer = Encoding.UTF8.GetBytes(responseBody);
            response.StatusCode = 200;
            await response.OutputStream.WriteAsync(responseBuffer, 0, responseBuffer.Length);
            Console.WriteLine("[SERVER] История успешно отправлена!");
        }


        private static UserHistory GetUserHistory(int userId)
        {
            var history = new UserHistory();

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();

                // Получаем историю транзакций
                string getTransactionsQuery = @"
                    SELECT t.Id, t.SenderId, t.ReceiverId, t.Amount, t.DateTime, 
                           sender.UserName AS SenderName, receiver.UserName AS ReceiverName
                    FROM dbo.[Transaction] t
                    INNER JOIN dbo.[User] sender ON t.SenderId = sender.Id
                    INNER JOIN dbo.[User] receiver ON t.ReceiverId = receiver.Id
                    WHERE t.SenderId = @UserId OR t.ReceiverId = @UserId
                    ORDER BY t.DateTime DESC";
                using (SqlCommand cmd = new SqlCommand(getTransactionsQuery, conn))
                {
                    cmd.Parameters.AddWithValue("@UserId", userId);
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var transaction = new TransactionHistory
                            {
                                Id = reader.GetInt32(0),
                                SenderId = reader.GetInt32(1),
                                ReceiverId = reader.GetInt32(2),
                                Amount = reader.GetInt32(3),
                                DateTime = reader.GetDateTime(4),
                                SenderName = reader.GetString(5),
                                ReceiverName = reader.GetString(6)
                            };
                            history.Transactions.Add(transaction);
                        }
                    }
                }

                // Получаем историю покупок
                string getPurchasesQuery = @"
                    SELECT p.Id, p.MerchId, p.Quantity, p.DateTime, m.Name AS MerchName
                    FROM dbo.Purchase p
                    INNER JOIN dbo.Merch m ON p.MerchId = m.Id
                    WHERE p.UserId = @UserId
                    ORDER BY p.DateTime DESC";
                using (SqlCommand cmd = new SqlCommand(getPurchasesQuery, conn))
                {
                    cmd.Parameters.AddWithValue("@UserId", userId);
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var purchase = new PurchaseHistory
                            {
                                Id = reader.GetInt32(0),
                                MerchId = reader.GetInt32(1),
                                Quantity = reader.GetInt32(2),
                                DateTime = reader.GetDateTime(3),
                                MerchName = reader.GetString(4)
                            };
                            history.Purchases.Add(purchase);
                        }
                    }
                }
            }

            return history;
        }

        private static bool ValidateUser(string username, string password, out int userId, out int balance, out string error)
        {
            userId = 0;
            balance = 0;
            error = "Ошибка аутентификации";

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                Console.WriteLine("[DB] Подключение к базе успешно!");

                string query = "SELECT Id, Balance FROM dbo.[User] WHERE UserName = @Username AND Password = @Password";
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@Username", username);
                    cmd.Parameters.AddWithValue("@Password", password);

                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            userId = reader.GetInt32(0);
                            balance = reader.GetInt32(1);
                            return true;
                        }
                    }
                }
            }
            error = "Неверное имя пользователя или пароль";
            return false;
        }

        private static bool ValidateJwtToken(string token, out int userId, out string username)
        {
            userId = 0;
            username = string.Empty;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(jwtSecretKey);

            try
            {
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };

                var principal = tokenHandler.ValidateToken(token, parameters, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;

                userId = int.Parse(jwtToken.Claims.First(c => c.Type == "userId").Value);
                username = jwtToken.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value;

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVER] Ошибка валидации токена: {ex.Message}");
                return false;
            }
        }

        private static string GenerateJwtToken(int userId, string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(jwtSecretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("userId", userId.ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, username),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static bool RegisterUser(string username, string password, out string error)
        {
            error = "";

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (SqlTransaction transaction = conn.BeginTransaction())
                {
                    try
                    {
                        // Находим максимальное значение Id
                        string getMaxIdQuery = "SELECT MAX(Id) FROM dbo.[User]";
                        int newId;
                        using (SqlCommand cmd = new SqlCommand(getMaxIdQuery, conn, transaction))
                        {
                            var result = cmd.ExecuteScalar();
                            newId = result == DBNull.Value ? 1 : Convert.ToInt32(result) + 1; // Если таблица пуста, начинаем с 1
                        }

                        // Хешируем пароль
                        string hashedPassword = HashPassword(password);

                        // Сохраняем нового пользователя с начальным балансом 1000 монет
                        string insertQuery = "INSERT INTO dbo.[User] (Id, UserName, Password, Balance) VALUES (@Id, @Username, @Password, @Balance)";
                        using (SqlCommand cmd = new SqlCommand(insertQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@Id", newId);
                            cmd.Parameters.AddWithValue("@Username", username);
                            cmd.Parameters.AddWithValue("@Password", hashedPassword);
                            cmd.Parameters.AddWithValue("@Balance", 1000); // Начальный баланс 1000 монет

                            cmd.ExecuteNonQuery();
                        }

                        transaction.Commit();
                        return true;
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        error = ex.Message;
                        return false;
                    }
                }
            }
        }

        private static bool SendCoins(int senderId, string toUser, int amount, out string error)
        {
            error = "";
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (SqlTransaction transaction = conn.BeginTransaction())
                {
                    try
                    {
                        // Проверка получателя
                        string getReceiverQuery = "SELECT Id FROM dbo.[User] WHERE UserName = @ToUser";
                        int receiverId;
                        using (SqlCommand cmd = new SqlCommand(getReceiverQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@ToUser", toUser);
                            var result = cmd.ExecuteScalar();
                            if (result == null)
                            {
                                error = "Получатель не найден";
                                return false;
                            }
                            receiverId = (int)result;
                        }

                        // Проверка баланса отправителя
                        string checkBalanceQuery = "SELECT Balance FROM dbo.[User] WHERE Id = @SenderId";
                        int senderBalance;
                        using (SqlCommand cmd = new SqlCommand(checkBalanceQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@SenderId", senderId);
                            senderBalance = (int)cmd.ExecuteScalar();
                        }

                        if (senderBalance < amount)
                        {
                            error = "Недостаточно средств";
                            return false;
                        }

                        // Списание средств
                        string deductQuery = "UPDATE dbo.[User] SET Balance = Balance - @Amount WHERE Id = @SenderId";
                        using (SqlCommand cmd = new SqlCommand(deductQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@Amount", amount);
                            cmd.Parameters.AddWithValue("@SenderId", senderId);
                            cmd.ExecuteNonQuery();
                        }

                        // Зачисление средств
                        string addQuery = "UPDATE dbo.[User] SET Balance = Balance + @Amount WHERE Id = @ReceiverId";
                        using (SqlCommand cmd = new SqlCommand(addQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@Amount", amount);
                            cmd.Parameters.AddWithValue("@ReceiverId", receiverId);
                            cmd.ExecuteNonQuery();
                        }

                        // Сохраняем данные о переводе в таблицу Transaction
                        SaveTransaction(senderId, receiverId, amount, conn, transaction);

                        transaction.Commit();
                        return true;
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        error = ex.Message;
                        return false;
                    }
                }
            }
        }

        private static bool PurchaseItem(int userId, string itemName, out string error)
        {
            error = "";
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (SqlTransaction transaction = conn.BeginTransaction())
                {
                    try
                    {
                        // Получаем информацию о товаре
                        string getMerchQuery = "SELECT Id, Price FROM dbo.Merch WHERE Name = @Name";
                        int merchId;
                        int price;
                        using (SqlCommand cmd = new SqlCommand(getMerchQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@Name", itemName);
                            using (SqlDataReader reader = cmd.ExecuteReader())
                            {
                                if (!reader.Read())
                                {
                                    error = "Товар не найден";
                                    return false;
                                }
                                merchId = reader.GetInt32(0);
                                price = reader.GetInt32(1);
                            }
                        }

                        // Проверяем баланс пользователя
                        string checkBalanceQuery = "SELECT Balance FROM dbo.[User] WHERE Id = @UserId";
                        int userBalance;
                        using (SqlCommand cmd = new SqlCommand(checkBalanceQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@UserId", userId);
                            userBalance = (int)cmd.ExecuteScalar();
                        }

                        if (userBalance < price)
                        {
                            error = "Недостаточно средств";
                            return false;
                        }

                        // Списываем стоимость товара
                        string deductQuery = "UPDATE dbo.[User] SET Balance = Balance - @Price WHERE Id = @UserId";
                        using (SqlCommand cmd = new SqlCommand(deductQuery, conn, transaction))
                        {
                            cmd.Parameters.AddWithValue("@Price", price);
                            cmd.Parameters.AddWithValue("@UserId", userId);
                            cmd.ExecuteNonQuery();
                        }

                        // Сохраняем данные о покупке в таблицу Purchase
                        SavePurchase(userId, merchId, 1, conn, transaction);

                        transaction.Commit();
                        return true;
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        error = ex.Message;
                        return false;
                    }
                }
            }
        }

        private static void SaveTransaction(int senderId, int receiverId, int amount, SqlConnection conn, SqlTransaction transaction)
        {
            // Находим максимальное значение Id
            string getMaxIdQuery = "SELECT MAX(Id) FROM dbo.[Transaction]";
            int newId;
            using (SqlCommand cmd = new SqlCommand(getMaxIdQuery, conn, transaction))
            {
                var result = cmd.ExecuteScalar();
                newId = result == DBNull.Value ? 1 : Convert.ToInt32(result) + 1; // Если таблица пуста, начинаем с 1
            }

            // Сохраняем данные о переводе
            string insertQuery = "INSERT INTO dbo.[Transaction] (Id, SenderId, ReceiverId, Amount, DateTime) VALUES (@Id, @SenderId, @ReceiverId, @Amount, @DateTime)";
            using (SqlCommand cmd = new SqlCommand(insertQuery, conn, transaction))
            {
                cmd.Parameters.AddWithValue("@Id", newId);
                cmd.Parameters.AddWithValue("@SenderId", senderId);
                cmd.Parameters.AddWithValue("@ReceiverId", receiverId);
                cmd.Parameters.AddWithValue("@Amount", amount);
                cmd.Parameters.AddWithValue("@DateTime", DateTime.UtcNow);

                cmd.ExecuteNonQuery();
            }
        }

        private static void SavePurchase(int userId, int merchId, int quantity, SqlConnection conn, SqlTransaction transaction)
        {
            // Находим максимальное значение Id
            string getMaxIdQuery = "SELECT MAX(Id) FROM dbo.Purchase";
            int newId;
            using (SqlCommand cmd = new SqlCommand(getMaxIdQuery, conn, transaction))
            {
                var result = cmd.ExecuteScalar();
                newId = result == DBNull.Value ? 1 : Convert.ToInt32(result) + 1; // Если таблица пуста, начинаем с 1
            }

            // Сохраняем данные о покупке
            string insertQuery = "INSERT INTO dbo.Purchase (Id, UserId, MerchId, Quantity, DateTime) VALUES (@Id, @UserId, @MerchId, @Quantity, @DateTime)";
            using (SqlCommand cmd = new SqlCommand(insertQuery, conn, transaction))
            {
                cmd.Parameters.AddWithValue("@Id", newId);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@MerchId", merchId);
                cmd.Parameters.AddWithValue("@Quantity", quantity);
                cmd.Parameters.AddWithValue("@DateTime", DateTime.UtcNow);

                cmd.ExecuteNonQuery();
            }
        }

        private static string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }

        public class AuthRequest { public string Username { get; set; } public string Password { get; set; } }
        public class SendCoinRequest { public string ToUser { get; set; } public int Amount { get; set; } }
        public class RegisterRequest { public string Username { get; set; } public string Password { get; set; } }

        public class UserHistory
        {
            public List<TransactionHistory> Transactions { get; set; } = new List<TransactionHistory>();
            public List<PurchaseHistory> Purchases { get; set; } = new List<PurchaseHistory>();
        }

        public class TransactionHistory
        {
            public int Id { get; set; }
            public int SenderId { get; set; }
            public int ReceiverId { get; set; }
            public int Amount { get; set; }
            public DateTime DateTime { get; set; }
            public string SenderName { get; set; }
            public string ReceiverName { get; set; }
        }

        public class PurchaseHistory
        {
            public int Id { get; set; }
            public int MerchId { get; set; }
            public int Quantity { get; set; }
            public DateTime DateTime { get; set; }
            public string MerchName { get; set; }
        }
    }
}
