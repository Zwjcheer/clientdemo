package cn.zifangsky.model;

/**
 * 百度返回的用户基本信息
 *
 * @author zifangsky
 * @date 2018/7/25
 * @since 1.0.0
 */
public class BaiduUser {

    /**
     * 百度的userId
     */
    private String userid;

    /**
     * 用户名
     */
    private String username;

    /**
     * 用户性别，0表示女性，1表示男性
     */
    private Integer sex;

    /**
     * 用户生日
     */
    private String birthday;

    /**
     * 用户描述
     */
    private String userdetail;

    /**
     * 是否绑定手机号
     */
    private Integer is_bind_mobile;

    /**
     * 是否已经实名认证
     */
    private Integer is_realname;

    public String getUserid() {
        return userid;
    }

    public void setUserid(String userid) {
        this.userid = userid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Integer getSex() {
        return sex;
    }

    public void setSex(Integer sex) {
        this.sex = sex;
    }

    public String getBirthday() {
        return birthday;
    }

    public void setBirthday(String birthday) {
        this.birthday = birthday;
    }

    public String getUserdetail() {
        return userdetail;
    }

    public void setUserdetail(String userdetail) {
        this.userdetail = userdetail;
    }

    public Integer getIs_bind_mobile() {
        return is_bind_mobile;
    }

    public void setIs_bind_mobile(Integer is_bind_mobile) {
        this.is_bind_mobile = is_bind_mobile;
    }

    public Integer getIs_realname() {
        return is_realname;
    }

    public void setIs_realname(Integer is_realname) {
        this.is_realname = is_realname;
    }

    @Override
    public String toString() {
        return "BaiduUser{" +
                "userid='" + userid + '\'' +
                ", username='" + username + '\'' +
                ", sex=" + sex +
                ", birthday='" + birthday + '\'' +
                ", userdetail='" + userdetail + '\'' +
                ", is_bind_mobile=" + is_bind_mobile +
                ", is_realname=" + is_realname +
                '}';
    }
}
