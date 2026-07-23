use crate::error::{LuckError, Result};
use crate::model::{Cookie, CookieCollection, SameSite};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortField {
    Name,
    Domain,
    Path,
    Expiration,
    Size,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QueryExpr {
    True,
    NameContains(String),
    ValueContains(String),
    DomainMatches(String),
    PathPrefix(String),
    Secure(bool),
    HttpOnly(bool),
    Session(bool),
    SameSite(SameSite),
    Expired(bool),
    And(Vec<QueryExpr>),
    Or(Vec<QueryExpr>),
    Not(Box<QueryExpr>),
}

impl QueryExpr {
    pub fn matches(&self, cookie: &Cookie) -> bool {
        match self {
            Self::True => true,
            Self::NameContains(value) => contains_case_insensitive(&cookie.name, value),
            Self::ValueContains(value) => contains_case_insensitive(&cookie.value, value),
            Self::DomainMatches(value) => cookie.domain_matches(value),
            Self::PathPrefix(value) => cookie.path.starts_with(value),
            Self::Secure(value) => cookie.secure == *value,
            Self::HttpOnly(value) => cookie.http_only == *value,
            Self::Session(value) => cookie.effective_session() == *value,
            Self::SameSite(value) => cookie.same_site == *value,
            Self::Expired(value) => cookie.is_expired_now() == *value,
            Self::And(expressions) => expressions.iter().all(|expression| expression.matches(cookie)),
            Self::Or(expressions) => expressions.iter().any(|expression| expression.matches(cookie)),
            Self::Not(expression) => !expression.matches(cookie),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CookieQuery {
    pub expression: QueryExpr,
    pub sort_field: SortField,
    pub sort_order: SortOrder,
    pub offset: usize,
    pub limit: Option<usize>,
}

impl Default for CookieQuery {
    fn default() -> Self {
        Self {
            expression: QueryExpr::True,
            sort_field: SortField::Domain,
            sort_order: SortOrder::Ascending,
            offset: 0,
            limit: None,
        }
    }
}

impl CookieQuery {
    pub fn execute(&self, collection: &CookieCollection) -> CookieCollection {
        let mut cookies: Vec<Cookie> = collection.iter().filter(|cookie| self.expression.matches(cookie)).cloned().collect();
        cookies.sort_by(|left, right| compare(left, right, self.sort_field));
        if self.sort_order == SortOrder::Descending {
            cookies.reverse();
        }
        let cookies = cookies
            .into_iter()
            .skip(self.offset)
            .take(self.limit.unwrap_or(usize::MAX))
            .collect();
        CookieCollection::new(cookies)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Ok(Self::default());
        }
        let mut parser = Parser { tokens, position: 0 };
        let expression = parser.parse_or()?;
        if parser.position != parser.tokens.len() {
            return Err(parser.error("unexpected trailing token"));
        }
        Ok(Self { expression, ..Self::default() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Colon,
    LParen,
    RParen,
    And,
    Or,
    Not,
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((offset, character)) = chars.next() {
        match character {
            c if c.is_whitespace() => {}
            ':' => tokens.push(Token::Colon),
            '(' => tokens.push(Token::LParen),
            ')' => tokens.push(Token::RParen),
            '"' | '\'' => {
                let quote = character;
                let mut value = String::new();
                let mut closed = false;
                while let Some((_, next)) = chars.next() {
                    if next == quote {
                        closed = true;
                        break;
                    }
                    if next == '\\' {
                        if let Some((_, escaped)) = chars.next() {
                            value.push(escaped);
                        }
                    } else {
                        value.push(next);
                    }
                }
                if !closed {
                    return Err(LuckError::Query { offset, message: "unterminated quoted string".into() });
                }
                tokens.push(Token::Word(value));
            }
            _ => {
                let mut word = String::from(character);
                while let Some((_, next)) = chars.peek().copied() {
                    if next.is_whitespace() || matches!(next, ':' | '(' | ')') {
                        break;
                    }
                    chars.next();
                    word.push(next);
                }
                match word.to_ascii_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Word(word)),
                }
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn parse_or(&mut self) -> Result<QueryExpr> {
        let mut expressions = vec![self.parse_and()?];
        while self.consume(&Token::Or) {
            expressions.push(self.parse_and()?);
        }
        Ok(if expressions.len() == 1 { expressions.remove(0) } else { QueryExpr::Or(expressions) })
    }

    fn parse_and(&mut self) -> Result<QueryExpr> {
        let mut expressions = vec![self.parse_unary()?];
        while self.consume(&Token::And) {
            expressions.push(self.parse_unary()?);
        }
        Ok(if expressions.len() == 1 { expressions.remove(0) } else { QueryExpr::And(expressions) })
    }

    fn parse_unary(&mut self) -> Result<QueryExpr> {
        if self.consume(&Token::Not) {
            return Ok(QueryExpr::Not(Box::new(self.parse_unary()?)));
        }
        if self.consume(&Token::LParen) {
            let expression = self.parse_or()?;
            if !self.consume(&Token::RParen) {
                return Err(self.error("expected ')'"));
            }
            return Ok(expression);
        }
        self.parse_term()
    }

    fn parse_term(&mut self) -> Result<QueryExpr> {
        let field = self.take_word()?;
        if !self.consume(&Token::Colon) {
            return Ok(QueryExpr::Or(vec![
                QueryExpr::NameContains(field.clone()),
                QueryExpr::DomainMatches(field),
            ]));
        }
        let value = self.take_word()?;
        match field.to_ascii_lowercase().as_str() {
            "name" => Ok(QueryExpr::NameContains(value)),
            "value" => Ok(QueryExpr::ValueContains(value)),
            "domain" => Ok(QueryExpr::DomainMatches(value)),
            "path" => Ok(QueryExpr::PathPrefix(value)),
            "secure" => Ok(QueryExpr::Secure(parse_bool(&value)?)),
            "httponly" | "http_only" => Ok(QueryExpr::HttpOnly(parse_bool(&value)?)),
            "session" => Ok(QueryExpr::Session(parse_bool(&value)?)),
            "expired" => Ok(QueryExpr::Expired(parse_bool(&value)?)),
            "samesite" | "same_site" => Ok(QueryExpr::SameSite(SameSite::from_label(&value))),
            _ => Err(self.error(&format!("unknown field {field:?}"))),
        }
    }

    fn take_word(&mut self) -> Result<String> {
        match self.tokens.get(self.position).cloned() {
            Some(Token::Word(value)) => {
                self.position += 1;
                Ok(value)
            }
            _ => Err(self.error("expected a word")),
        }
    }

    fn consume(&mut self, token: &Token) -> bool {
        if self.tokens.get(self.position) == Some(token) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, message: &str) -> LuckError {
        LuckError::Query { offset: self.position, message: message.to_owned() }
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(LuckError::InvalidArgument(format!("expected boolean, received {value:?}"))),
    }
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn compare(left: &Cookie, right: &Cookie, field: SortField) -> Ordering {
    match field {
        SortField::Name => left.name.cmp(&right.name),
        SortField::Domain => left.domain.cmp(&right.domain).then_with(|| left.name.cmp(&right.name)),
        SortField::Path => left.path.cmp(&right.path).then_with(|| left.name.cmp(&right.name)),
        SortField::Expiration => left.expiration_date.partial_cmp(&right.expiration_date).unwrap_or(Ordering::Equal),
        SortField::Size => left.estimated_bytes().cmp(&right.estimated_bytes()),
    }
}
