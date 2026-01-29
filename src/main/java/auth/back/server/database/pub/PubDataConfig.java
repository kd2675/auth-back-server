package auth.back.server.database.pub;

import auth.back.server.datasource.RoutingDataSource;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        basePackages = {"auth.back.server.database.pub.repository"},
        entityManagerFactoryRef = "pubEntityManagerFactory",
        transactionManagerRef = "pubTransactionManager"
)
public class PubDataConfig {
    @Bean
    @Primary
    @ConfigurationProperties("database.datasource.pub.master")
    public DataSourceProperties pubMasterDatasourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Primary
    @ConfigurationProperties("database.datasource.pub.master.configure")
    public DataSource pubMasterDatasource() {
        return pubSlave1DatasourceProperties()
                .initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    @Bean
    @ConfigurationProperties("database.datasource.pub.slave1")
    public DataSourceProperties pubSlave1DatasourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @ConfigurationProperties("database.datasource.pub.slave1.configure")
    public DataSource pubSlave1Datasource() {
        return pubSlave1DatasourceProperties()
                .initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    @Bean(name = "pubEntityManagerFactory")
    @Primary
    public LocalContainerEntityManagerFactoryBean pubEntityManagerFactory(
            EntityManagerFactoryBuilder builder,
            @Qualifier("pubMasterDatasource") DataSource masterDataSource,
            @Qualifier("pubSlave1Datasource") DataSource slave1DataSource
    ) {
        RoutingDataSource routingDataSource = new RoutingDataSource();
        Map<Object, Object> datasourceMap = new HashMap<Object, Object>() {
            {
                put("master", masterDataSource);
                put("slave", slave1DataSource);
            }
        };

        routingDataSource.setTargetDataSources(datasourceMap);
        routingDataSource.setDefaultTargetDataSource(masterDataSource);
        routingDataSource.afterPropertiesSet();

        HashMap<String, Object> properties = new HashMap<>();
        properties.put("hibernate.hbm2ddl.auto", "validate");
//        properties.put("hibernate.hbm2ddl.auto", "create");
        properties.put("hibernate.default_batch_fetch_size", 1000);
        properties.put("hibernate.show_sql", false);
        properties.put("hibernate.format_sql", true);
        properties.put("hibernate.use_sql_comments", true);

        return builder.dataSource(new LazyConnectionDataSourceProxy(routingDataSource))
                .packages("auth.back.server.database.pub.entity")
//                .packages("org.example.database.database.auth.rep.jpa")
                .properties(properties)
                .persistenceUnit("pubEntityManager")
                .build();
    }

    @Bean(name = "pubTransactionManager")
    @Primary
    public PlatformTransactionManager pubTransactionManager(
            final @Qualifier("pubEntityManagerFactory") LocalContainerEntityManagerFactoryBean localContainerEntityManagerFactoryBean
    ) {
        return new JpaTransactionManager(localContainerEntityManagerFactoryBean.getObject());
    }
}