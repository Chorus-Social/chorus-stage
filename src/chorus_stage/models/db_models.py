from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "tbl_users"
    
    id = Column(Integer, primary_key=True)
    user_key = Column(String(18), unique=True, nullable=False)
    display_name = Column(Text, nullable=False) # Changed back to not nullable
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    metadata = Column(JSON, nullable=True)

    # --- ADDED RELATIONSHIPS ---
    # One-to-many: A user can create many posts
    posts_authored = relationship("Posts", back_populates="author")
    
    # Many-to-many: A user can be in many communities
    communities = relationship("Community", secondary="tbl_community_members", back_populates="members")
    
    # Many-to-many: A user can vote on many posts
    votes = relationship("Votes", back_populates="user")


class Posts(Base):
    __tablename__ = "tbl_posts"
    
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey("tbl_posts.id"), nullable=True)
    is_rephrasing = Column(Boolean, index=True)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    metadata = Column(JSON, nullable=True)
    
    community_id = Column(Integer, ForeignKey('tbl_communities.id'), nullable=False)
    
    # --- ADDED AUTHOR FOREIGN KEY and RELATIONSHIP ---
    author_id = Column(Integer, ForeignKey('tbl_users.id'), nullable=False)
    author = relationship("User", back_populates="posts_authored")
    
    community = relationship("Community", back_populates="posts")
    
    # --- ADDED RELATIONSHIPS ---
    # Many-to-many: A post can have many votes
    votes = relationship("Votes", back_populates="post")
    
    # Self-referencing: A post (comment) has one parent, a parent can have many children (comments)
    parent = relationship("Posts", remote_side=[id], back_populates="children")
    children = relationship("Posts", back_populates="parent")


class Community(Base):
    __tablename__ = "tbl_communities"
    
    id = Column(Integer, primary_key=True)
    display_name = Column(String(32), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    metadata = Column(JSON, nullable=True)
    
    # --- ADDED RELATIONSHIPS ---
    # One-to-many: A community has many posts
    posts = relationship("Posts", back_populates="community")
    
    # Many-to-many: A community has many members (users)
    members = relationship("User", secondary="tbl_community_members", back_populates="communities")


class Votes(Base):
    __tablename__ = "tbl_votes"
    
    post_id = Column(Integer, ForeignKey("tbl_posts.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("tbl_users.id"), primary_key=True)
    vote = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    
    # --- ADDED RELATIONSHIPS ---
    # These link the vote back to the specific user and post objects
    user = relationship("User", back_populates="votes")
    post = relationship("Posts", back_populates="votes")


class CommunityMembers(Base):
    __tablename__ = "tbl_community_members"
    
    community_id = Column(Integer, ForeignKey("tbl_communities.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("tbl_users.id"), primary_key=True)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)

class PostCoAuthors(Base):
    __tablename__ = "tbl_post_coauthors"
    
    post_id = Column(Integer, ForeignKey("tbl_posts.id"), primary_key=True, nullable=False)
    user_id = Column(Integer, ForeignKey("tbl_users.id"), primary_key=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)